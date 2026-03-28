using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

using DNS.Packet;
using DNS.Packet.Enum;
using DNS.Packet.Serializable;
using DNS.Storage;

using YamlDotNet.Serialization;  

namespace DNS;

// ReSharper disable once InconsistentNaming
public class DNSServer : IDisposable
{
    #region Constants

    private const string ConfigPath = "config.yaml";
    private const string LogPath = "dns.log";

    #endregion
    
    #region Fields
    
    private bool _disposed = false;
    private readonly ManualResetEventSlim _shutdownEvent = new(false);
    
    private readonly SimpleRecordHolder<string, DNSResourceRecord> _records = new();
    private readonly HashSet<string> _authoritativeZones = new(StringComparer.OrdinalIgnoreCase);

    private readonly CancellationTokenSource _cts = new();
    
    private readonly Logger _logger = new(LogPath);
    private readonly Thread? _listenThread;
    private UdpClient? _udpClient;
    
    #endregion

    #region Constructors
        
    public DNSServer(int port)
    {
        SetupHandlers();
        LoadConfig();
        
        _listenThread = new Thread(() => ListenAsync(port)) 
        { 
            IsBackground = true, 
            Name = "DNS Listener Thread" 
        };
        _listenThread.Start();
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
        Console.WriteLine("Received SIGINT. Shutting down gracefully...");
        Dispose();
    }

    private void OnPosixSignal(PosixSignalContext context)
    {
        // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
        switch (context.Signal)
        {
            case PosixSignal.SIGHUP:
                Console.WriteLine("Received SIGHUP - reloading YAML configuration...");
                LoadConfig();
                return;
            default:
                Console.WriteLine($"Received {context.Signal}. Shutting down gracefully...");
                Dispose();
                break;
        }
    }

    #endregion

    #region Configuration

    private void LoadConfig()
    {
        _records.Clear();
        _authoritativeZones.Clear();
        
        try
        {
            var deserializer = new DeserializerBuilder().Build();
            var yaml = File.ReadAllText(ConfigPath);
            var config = deserializer.Deserialize<DNSConfig>(yaml);

            if (config?.Zones == null || config.Zones.Count == 0) return;

            foreach (var zone in config.Zones.Where(zone => !string.IsNullOrWhiteSpace(zone.Domain)))
            {
                _authoritativeZones.Add(zone.Domain);
                
                var soaRecord = new DNSResourceRecord(
                    zone.Domain, 
                    DNSType.SOA, 
                    DNSClass.IN, 
                    zone.SOA.Minimum, 
                    DNSHelper.CreateSOARData(
                        zone.SOA.MName,
                        zone.SOA.RName,
                        zone.SOA.Serial,
                        zone.SOA.Refresh,
                        zone.SOA.Retry,
                        zone.SOA.Expire,
                        zone.SOA.Minimum
                        )
                    );
                
                _records.Add(zone.Domain, soaRecord);

                foreach (var nsRecord in
                         from ns 
                         in zone.NSRecords
                         where !string.IsNullOrWhiteSpace(ns)
                         select DNSHelper.CreateNameRData(ns)
                         into nsData
                         select new DNSResourceRecord(
                             zone.Domain,
                             DNSType.NS,
                             DNSClass.IN,
                             3600,
                             nsData
                             )
                         )
                {
                    _records.Add(zone.Domain, nsRecord);
                }
                
                foreach (var rec in 
                         zone.ARecords.Where(
                             rec => 
                                 !string.IsNullOrWhiteSpace(rec.Name) && 
                                 !string.IsNullOrWhiteSpace(rec.Value)
                                 )
                         )
                {
                    var name = DNSHelper.GetFullQName(rec.Name, zone.Domain);
                    _records.Add(
                        name,
                        new DNSResourceRecord(
                            name,
                            DNSType.A, 
                            DNSClass.IN,
                            rec.TTL,
                            IPAddress.Parse(rec.Value).GetAddressBytes()
                        )
                    );
                }
                
                foreach (var rec in 
                         zone.AAAARecords.Where(
                             rec => 
                                 !string.IsNullOrWhiteSpace(rec.Name) && 
                                 !string.IsNullOrWhiteSpace(rec.Value)
                                 )
                         )
                {
                    var name = DNSHelper.GetFullQName(rec.Name, zone.Domain);
                    _records.Add(
                        name,
                        new DNSResourceRecord(
                                name,
                                DNSType.AAAA, 
                                DNSClass.IN,
                                rec.TTL,
                                IPAddress.Parse(rec.Value).GetAddressBytes()
                            )
                        );
                }
            }

            Console.WriteLine($"Successfully loaded {config.Zones.Count} zone(s) from {ConfigPath}");
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Failed to load YAML config at '{ConfigPath}'");
        }
    }
    
    #endregion

    #region Listening

    private async void ListenAsync(int port)
    { 
        try
        {
            _udpClient = new UdpClient(port);
            
            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    var result = await _udpClient.ReceiveAsync(_cts.Token);
                    var data = result.Buffer;
                    _ = Task.Run(() => ProcessQuery(result.RemoteEndPoint, data), _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync($"Failed to listen: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"Failed to listen: {ex.Message}");
        }
        finally
        {
            _udpClient?.Dispose();
        }
    }

    private void ProcessQuery(IPEndPoint remoteEndPoint, byte[] data)
    {
        const int maxPacketSize = 512;
        
        try
        {
            var query = new DNSPacket(data.AsSpan());

            if (query.Questions.Length == 0)
                return;

            var builder = new DNSResponseBuilder(query)
                .SetAuthoritative()
                .SetRecursionAvailable(false);

            do
            {
                var question = query.Questions[0];
                
                var isInZone = _authoritativeZones.Any(
                    zone => 
                        question.Name.Equals(zone, StringComparison.OrdinalIgnoreCase) || 
                        question.Name.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase)
                );

                if (!isInZone)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.Refused);
                    break;
                }
                
                var nameRecords = _records[question.Name];

                if (nameRecords.Count == 0)
                {
                    builder.SetResponseCode(DNSHeader.ResponseCode.DomainNotExist);
                    break;
                } 
                
                builder.AddAnswers(
                    from record in nameRecords 
                    where record.Type == question.Type 
                    select record
                    );              
                
                builder.SetResponseCode(DNSHeader.ResponseCode.NoError);
                
            } while (false);
            
            var responsePacket = builder.Build();
            
            Span<byte> buffer = stackalloc byte[maxPacketSize];
            var offset = 0;
            
            responsePacket.Serialize(buffer, ref offset);

            var response = new byte[offset];
            buffer[..offset].CopyTo(response);
            
            _udpClient?.Send(response, offset, remoteEndPoint);

            _logger.LogRequestResponse(query, responsePacket, remoteEndPoint);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error processing packet: {ex.Message}");
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
        if (_disposed)
            return;

        _disposed = true;

        const int listenThreadTimeout = 2000;

        GC.SuppressFinalize(this);
        _cts.Cancel();
        _udpClient?.Dispose();
        _cts.Dispose();
        _listenThread?.Join(listenThreadTimeout);

        _shutdownEvent.Set();
    }

    #endregion
}