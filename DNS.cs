using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using DNS.Packet;
using DNS.Packet.Enum;
using DNS.Packet.Serializable;
using DNS.Storage;

using log4net;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace DNS;

// ReSharper disable once InconsistentNaming
public class DNSServer : IDisposable
{
    #region Constants

    private const string ConfigPath = "config.yaml";
    
    private static JsonSerializerOptions _jsonOptions = new()
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

    private readonly SimpleRecordHolder<string, DNSResourceRecord> _records = new();
    private readonly HashSet<string> _authoritativeZones = new(StringComparer.OrdinalIgnoreCase);

    private readonly CancellationTokenSource _cts = new();

    private readonly ILog _logger = LogManager.GetLogger(typeof(DNSServer));
    private readonly Task? _listenerTask;
    private UdpClient? _udpClient;

    private readonly Lock _configLock = new();

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

    private void LoadConfig()
    {
        lock (_configLock)
        {
            _records.Clear();
            _authoritativeZones.Clear();

            try
            {
                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(NullNamingConvention.Instance)
                    .Build();

                var yaml = File.ReadAllText(ConfigPath);

                var config = deserializer.Deserialize<DNSConfig?>(yaml);

                if (config?.Zones is null || config.Zones.Count == 0)
                {
                    _logger.Warn("No zones found in YAML configuration - server will be empty.");
                    return;
                }

                var zones = config.Zones!;

                foreach (var zone in zones)
                {
                    if (string.IsNullOrWhiteSpace(zone.Domain))
                    {
                        _logger.Warn("While parsing config encountered zone without domain, skipping");
                        continue;
                    }

                    if (zone.Soa is null)
                    {
                        _logger.Warn("While parsing config encountered zone without SOA record, skipping");
                        continue;
                    }

                    if (zone.NSRecords is null || zone.NSRecords!.Count == 0)
                    {
                        _logger.Warn("While parsing config encountered zone without NS records, skipping");
                        continue;
                    }

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

                    // ReSharper disable once InconsistentNaming
                    var ARecordsLoaded = LoadARecords(zone.Domain, zone.ARecords ?? Enumerable.Empty<ARecord>());

                    // ReSharper disable once InconsistentNaming
                    var AAAARecordsLoaded =
                        LoadAAAARecords(zone.Domain, zone.AAAARecords ?? Enumerable.Empty<AAAARecord>());

                    _logger.Info(
                        $"Successfully loaded zone {zone.Domain} with {ARecordsLoaded} A records and {AAAARecordsLoaded} AAAA records.");
                }
            }
            catch (Exception e)
            {
                _logger.Error("Encountered unexpected error while loading zones", e);
            }
        }
    }
    
    // ReSharper disable once InconsistentNaming
    private bool TryLoadSOA(string domain, SOARecord record)
    {
        if (record.Serial is null)
        {
            _logger.Warn(
                $"While parsing zone {domain}, encountered SOA record without serial, skipping");
            return false;
        }

        if (record.Refresh is null)
        {
            _logger.Warn(
                $"While parsing zone {domain}, encountered SOA record without refresh, skipping");
            return false;
        }
        
        if (record.Retry is null)
        {
            _logger.Warn(
                $"While parsing zone {domain}, encountered SOA record without retry, skipping");
            return false;
        }
        
        if (record.Minimum is null)
        {
            _logger.Warn(
                $"While parsing zone {domain}, encountered SOA record without minimum, skipping");
            return false;
        }
        
        _records.Add(
            domain,
            new DNSResourceRecord(
                domain,
                DNSType.SOA,
                DNSClass.IN,
                record.Minimum!.Value,
                DNSHelper.CreateSOARData(
                    record.MName ?? string.Empty,
                    record.RName ?? string.Empty,
                    record.Serial!.Value,
                    record.Refresh!.Value,
                    record.Retry!.Value,
                    record.Expire ?? 0,
                    record.Minimum!.Value
                )
            )
        );
        return true;
    }

    // ReSharper disable once InconsistentNaming    
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
                address!.AddressFamily != AddressFamily.InterNetwork
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
    
    // ReSharper disable once InconsistentNaming
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
                address!.AddressFamily != AddressFamily.InterNetworkV6
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

    private async Task ListenAsync(int port)
    { 
        try
        {
            _udpClient = new UdpClient(port);
            
            while (!_cts.Token.IsCancellationRequested)
            {
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
                    _logger.Error("Encountered unexpected error while listening", e);
                }
            }
        }
        catch (Exception e)
        {
            _logger.Error("Failed to establish udp client", e);
        }
        finally
        {
            _udpClient?.Dispose();
        }
    }

    private void ProcessQuery(IPEndPoint remoteEndPoint, byte[] data)
    {
        const int maxPacketSize = 4096;
        
        try
        {
            var query = new DNSPacket(data.AsSpan());

            if (query.Questions.Length == 0)
                return;

            var builder = new DNSResponseBuilder(query)
                .SetAuthoritative()
                .SetRecursionAvailable(false);

            var question = query.Questions[0];

            var isInZone = _authoritativeZones.Any(zone =>
                question.Name.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                question.Name.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase)
            );
            
            if (!isInZone)
            {
                builder.SetResponseCode(DNSHeader.ResponseCode.Refused);
            }
            else
            {
                var nameRecords = _records[question.Name];

                if (nameRecords.Count == 0)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.DomainDoesNotExist);
                } 
                else 
                { 
                    builder.AddAnswers(
                        from record in nameRecords 
                        where record.Type == question.Type 
                        select record
                    );              
                
                    builder.SetResponseCode(DNSHeader.ResponseCode.NoError);
                }
            }
            
            var responsePacket = builder.Build();
            
            Span<byte> buffer = stackalloc byte[maxPacketSize];
            
            var offset = 0;
            
            responsePacket.Serialize(buffer, ref offset);

            var response = new byte[offset];
            buffer[..offset].CopyTo(response);
            
            _udpClient?.Send(response, offset, remoteEndPoint);

            var json = new
            {
                remoteEndPoint,
                query,
                response,
            };
            
            _logger.Info($"Processed: {JsonSerializer.Serialize(json, _jsonOptions)}");
        }
        catch (Exception ex)
        {
            _logger.Error($"Error processing packet: {ex.Message}", ex);
        }
    }

    #endregion

    #region Shutdown

    public void WaitForShutdown()
    {
        _shutdownEvent.Wait();
    }
    
    public void Dispose()
    {
        if (_disposed) return;

        _disposed = true;

        const int listenThreadTimeout = 2000;

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