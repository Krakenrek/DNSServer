using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using DNS.Packet;
using DNS.Packet.Enum;
using DNS.Packet.Serializable;
using DNS.Storage;
using DNS.Config;
using DNS.Config.Record;
using log4net;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace DNS;

/// <summary>
/// A lightweight, authoritative DNS server implementation.
/// </summary>
public class DNSServer : IDisposable
{
    #region Constants

    private const string ConfigPath = "config.yaml";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters =
        {
            new DNSPacketJsonConverter(),
            new JsonStringEnumConverter()
        }
    };

    #endregion

    #region Fields

    private bool _disposed;
    private readonly ManualResetEventSlim _shutdownEvent = new(false);

    private readonly Lock _configLock = new();
    private readonly SimpleRecordHolder<string, DNSResourceRecord> _records = new();

    private readonly HashSet<string> _authoritativeZones = new(StringComparer.OrdinalIgnoreCase);

    //TODO: Rework
    private readonly Dictionary<string, DNSResourceRecord> _soaRecords = new(StringComparer.OrdinalIgnoreCase);

    private readonly CancellationTokenSource _cts = new();
    private UdpClient? _udpClient;
    private readonly Task? _listenerTask;

    private readonly ILog _logger = LogManager.GetLogger(typeof(DNSServer));

    #endregion

    #region Constructors

    public DNSServer(int port)
    {
        SetupHandlers();
        LoadConfig();

        _listenerTask = Task.Run(() => ListenAsync(port));
    }

    #endregion

    #region Handlers

    private void SetupHandlers()
    {
        Console.CancelKeyPress += OnConsoleCancelKeyPress;

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
           )
            return;
        PosixSignalRegistration.Create(PosixSignal.SIGTERM, OnPosixSignal);
        PosixSignalRegistration.Create(PosixSignal.SIGHUP, OnPosixSignal);
    }

    private void OnConsoleCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = true;
        _logger.Info("Received SIGINT. Shutting down gracefully...");
        Dispose();
    }

    private void OnPosixSignal(PosixSignalContext context)
    {
        // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
        switch (context.Signal)
        {
            case PosixSignal.SIGHUP:
                _logger.Info("Received SIGHUP. Reloading YAML configuration...");
                LoadConfig();
                return;
            default:
                _logger.Info($"Received {context.Signal}. Shutting down gracefully...");
                Dispose();
                break;
        }
    }

    #endregion

    #region Configuration

    /// <summary>
    /// Reads the 'config.yaml' file and populates the internal record cache.
    /// This method, I think, is thread-safe.
    /// </summary>
    private void LoadConfig()
    {
        lock (_configLock)
        {
            //Clearing current records
            _records.Clear();
            _authoritativeZones.Clear();
            _soaRecords.Clear();

            try
            {
                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(NullNamingConvention.Instance)
                    .Build();

                var yaml = File.ReadAllText(ConfigPath);

                var config = deserializer.Deserialize<DNSConfig?>(yaml);

                //Validation: Ensure the zone has a domain, SOA, and Name Servers
                if (config?.Zones is null || config.Zones.Count == 0)
                {
                    _logger.Warn("No zones found in YAML configuration - server will be empty.");
                    return;
                }

                var zones = config.Zones!;

                foreach (var zone in zones)
                {
                    if (string.IsNullOrWhiteSpace(zone.Domain) || 
                        zone.Soa is null ||
                        (zone.NSRecords?.Count ?? 0) == 0
                        )
                    {
                        _logger.Warn($"Skipping incomplete zone definition for {zone.Domain ?? "Unknown"}...");
                        continue;
                    }

                    // Attempt to load the SOA record
                    if (!TryLoadSOA(zone.Domain!, zone.Soa!)) continue;

                    _authoritativeZones.Add(zone.Domain);

                    _records.AddRange(
                        zone.Domain,
                        zone.NSRecords!
                            .Select(DNSHelper.CreateNameRData)
                            .Select(data =>
                                new DNSResourceRecord(
                                    zone.Domain,
                                    DNSType.NS,
                                    DNSClass.IN,
                                    3600,
                                    data
                                )
                            )
                    );
                    
                    // Bulk load A and IPv6 AAAA records
                    var aCount = LoadARecords(zone.Domain, zone.ARecords ?? Enumerable.Empty<ARecord>());
                    var aaaaCount =
                        LoadAAAARecords(zone.Domain, zone.AAAARecords ?? Enumerable.Empty<AAAARecord>());

                    _logger.Info($"Zone {zone.Domain} loaded: {aCount} A, {aaaaCount} AAAA records.");
                }
            }
            catch (FileNotFoundException)
            {
                _logger.Warn("No configuration file found in YAML configuration - server will be empty.");
            }
            catch (Exception e)
            {
                _logger.Error("Critical failure during configuration loading", e);
            }
        }
    }
    
    /// <summary>
    /// Validates and converts a YAML SOA definition into a binary DNS Resource Record.
    /// </summary>
    private bool TryLoadSOA(string domain, SOARecord record)
    {
        if (record.Serial is null || 
            record.Refresh is null || 
            record.Retry is null ||
            record.Minimum is null
            ) 
        {
            _logger.Warn(
                $"While parsing zone {domain}, encountered incomplete SOA record skipping...");
            return false;
        }

        var soa = new DNSResourceRecord(
            domain,
            DNSType.SOA,
            DNSClass.IN,
            record.Minimum!.Value,
            DNSHelper.CreateSOAData(
                record.MName ?? string.Empty,
                record.RName ?? string.Empty,
                record.Serial!.Value,
                record.Refresh!.Value,
                record.Retry!.Value,
                record.Expire ?? 0,
                record.Minimum!.Value
            )
        );

        _records.Add(
            domain,
            soa
        );

        _soaRecords[domain] = soa;

        return true;
    }
    
    /// <summary>
    /// Bulk load A records in internal storage.
    /// </summary>
    /// <param name="domain">Domain where to load records.</param>
    /// <param name="records">Records to load.</param>
    /// <returns>Count of successfully loaded records.</returns>
    private int LoadARecords(string domain, IEnumerable<ARecord> records)
    {
        var loaded = 0;

        foreach (var record in records)
        {
            if (record.Name is null)
            {
                _logger.Warn(
                    $"While parsing zone {domain}, encountered A record without name, skipping");
                continue;
            }

            if (string.IsNullOrWhiteSpace(record.Value))
            {
                _logger.Warn(
                    $"While parsing zone {domain}, encountered A record without value, skipping");
                continue;
            }

            var name = DNSHelper.GetFullQName(record.Name!, domain);

            if (!IPAddress.TryParse(record.Value!, out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork
               )
            {
                _logger.Warn(
                    $"While parsing zone {record}, encountered A record with wrong value format, skipping");
                continue;
            }

            _records.Add(
                name,
                new DNSResourceRecord(
                    name,
                    DNSType.A,
                    DNSClass.IN,
                    record.TTL,
                    address.GetAddressBytes()
                )
            );

            loaded++;
        }

        return loaded;
    }
    
    /// <summary>
    /// Bulk load AAAA records in internal storage.
    /// </summary>
    /// <param name="domain">Domain where to load records.</param>
    /// <param name="records">Records to load.</param>
    /// <returns>Count of successfully loaded records.</returns>
    private int LoadAAAARecords(string domain, IEnumerable<AAAARecord> records)
    {
        var loaded = 0;

        foreach (var record in records)
        {
            if (record.Name is null)
            {
                _logger.Warn(
                    $"While parsing zone {domain}, encountered A record without name, skipping");
                continue;
            }

            if (string.IsNullOrWhiteSpace(record.Value))
            {
                _logger.Warn(
                    $"While parsing zone {domain}, encountered A record without value, skipping");
                continue;
            }

            var name = DNSHelper.GetFullQName(record.Name!, domain);

            if (!IPAddress.TryParse(record.Value!, out var address) ||
                address.AddressFamily != AddressFamily.InterNetworkV6
               )
            {
                _logger.Warn(
                    $"While parsing zone {record}, encountered A record with wrong value format, skipping");
                continue;
            }

            _records.Add(
                name,
                new DNSResourceRecord(
                    name,
                    DNSType.AAAA,
                    DNSClass.IN,
                    record.TTL,
                    address.GetAddressBytes()
                )
            );

            loaded++;
        }

        return loaded;
    }

    #endregion

    #region Listening

    /// <summary>
    /// Starts listening UDP traffic on given port.
    /// Proceeds to process retrieved packets asynchronously.
    /// </summary>
    /// <param name="port">Port to listen.</param>
    private async Task ListenAsync(int port)
    {
        try
        {
            _udpClient = new UdpClient(port);

            while (!_cts.Token.IsCancellationRequested)
                try
                {
                    var result = await _udpClient.ReceiveAsync();
                    var data = result.Buffer;
                    _ = Task.Run(() => ProcessQuery(result.RemoteEndPoint, data), _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException e)
                    when (e.SocketErrorCode is SocketError.OperationAborted or SocketError.Interrupted)
                {
                    break;
                }
                catch (Exception e)
                {
                    _logger.Fatal("Encountered unexpected error while listening", e);
                }
        }
        catch (Exception e)
        {
            _logger.Fatal("Failed to establish udp client", e);
        }
        finally
        {
            Dispose();
        }
    }

    /// <summary>
    /// Process given UDP packets and send response to provided endpoint.
    /// </summary>
    /// <param name="remoteEndPoint">Endpoint to send to.</param>
    /// <param name="queryData">Raw byte representation of UDP packet.</param>
    private void ProcessQuery(IPEndPoint remoteEndPoint, byte[] queryData)
    {
        DNSPacket query;
        DNSResponseBuilder builder;

        try
        {
            query = new DNSPacket(queryData.AsSpan());

            builder = new DNSResponseBuilder(query)
                .SetAuthoritative()
                .SetRecursionAvailable(false);

            do
            {
                //Not query -> Not Implemented
                if (query.Header.OpCode != DNSHeader.OperationCode.Query)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.NotImplemented);
                    break;
                }
                
                //Without questions -> Empty Response + NoError
                if (query.Questions.Length == 0)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.NoError);
                    break;
                }

                //Ignore queries with multiple questions
                if (query.Questions.Length > 1)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.FormatError);
                    break;
                }

                var question = query.Questions[0];

                var zone = _authoritativeZones.FirstOrDefault(z =>
                    question.Name.Equals(z, StringComparison.OrdinalIgnoreCase) ||
                    question.Name.EndsWith("." + z, StringComparison.OrdinalIgnoreCase)
                );

                var isInZone = zone is not null;

                // Not in zone -> Refuse
                if (!isInZone)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.Refused);
                    break;
                }

                var nameRecords = _records[question.Name];

                //No records -> Not Existing Domain + SOA Record
                if (nameRecords.Count == 0)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.DomainDoesNotExist);
                    var unwrapped = zone!;
                    builder.AddAuthority(_soaRecords[unwrapped]);
                    break;
                }

                //No satisfying answers -> Empty Response + NoError
                var answers = nameRecords.Where(record => record.Type == question.Type);

                builder.AddAnswers(answers);

                builder.SetResponseCode(DNSHeader.ResponseCode.NoError);
            } while (false);
        }
        catch (DnsParseException e) when (e.Context == DnsParseException.ParseContext.Header)
        {
            //Seems like garbage
            _logger.Warn("Encountered garbage instead of DNSHeader");
            return;
        }
        catch (DnsParseException e) when (e.Context != DnsParseException.ParseContext.Question)
        {
            //Can't parse -> Format Error
            builder = DNSResponseBuilder.fromOnlyHeader(queryData.AsSpan());
            query = builder.Build();
            builder.SetAuthoritative()
                .SetRecursionAvailable(false)
                .SetResponseCode(DNSHeader.ResponseCode.FormatError);
        }
        catch (Exception e)
        {
            //Something terrible happened
            _logger.Error("Encountered unexpected error while processing query, not sending response", e);
            return;
        }

        var response = builder.Build();

        Dictionary<string, int> compressionTable = new(StringComparer.OrdinalIgnoreCase);
        
        //Allocate sufficient buffer on stack
        Span<byte> buffer = stackalloc byte[response.GetSize(compressionTable)];

        //Set truncate if exceed
        if (buffer.Length > response.MaxPacketSize)
        {
            builder.SetTruncated();
            response = builder.Build();
        }

        //Reset buffer, for propper compression in serializing.
        compressionTable.Clear();

        var offset = 0;
        response.Serialize(buffer, ref offset, compressionTable);

        //Resize
        var responseSize = Math.Min(buffer.Length, response.MaxPacketSize);
        var responseData = new byte[responseSize];

        buffer[..responseSize].CopyTo(responseData);

        try
        {
            _udpClient?.Send(responseData, offset, remoteEndPoint);

            var json = new
            {
                timestamp = DateTimeOffset.UtcNow,
                remoteEndPoint = remoteEndPoint.ToString(),
                query,
                response
            };

            _logger.Info($"Processed: {JsonSerializer.Serialize(json, JsonOptions)}");
        }
        catch (Exception ex)
        {
            //Maybe this should be FATAL
            _logger.Error("Error sending response packet", ex);
        }
    }

    #endregion

    #region Shutdown

    /// <summary>
    /// Makes current Thread sleep until server goes down
    /// </summary>
    public void WaitForShutdown()
    {
        _shutdownEvent.Wait();
    }

    /// <summary>
    /// Disposes instances.
    /// Frees all allocated resources.
    /// Stops listen thread.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        _disposed = true;

        const int listenThreadTimeout = 1000;

        GC.SuppressFinalize(this);
        _cts.Cancel();
        _udpClient?.Close();
        _udpClient?.Dispose();
        _cts.Dispose();
        _listenerTask?.Wait(listenThreadTimeout);

        _shutdownEvent.Set();
    }

    #endregion
}