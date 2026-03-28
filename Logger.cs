using System.Net;
using System.Text.Json;
using DNS.Packet.Serializable;

namespace DNS;

public class Logger
{
    #region Properties
    
    public string Path { get; init; }
    
    #endregion

    #region Constructors

    public Logger(string path)
    {
        Path = path;
    }

    #endregion

    #region Public Methods

    public void Log(string message)
    {
        try
        {
            File.AppendAllText(Path, message + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to write to log file: {ex.Message}");
        }
    }
    
    public void LogRequestResponse(DNSPacket query, DNSPacket response, IPEndPoint remote)
    {
        var logEntry = new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            client_ip = remote.Address.ToString(),
            query,
            response
        };
        
        Log(JsonSerializer.Serialize(logEntry));
    }
    
    #endregion
}