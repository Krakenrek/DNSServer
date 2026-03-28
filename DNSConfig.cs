// ReSharper disable CollectionNeverUpdated.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming
namespace DNS;

public class DNSConfig
{
    public List<ZoneConfig> Zones { get; set; } = [];
}

public class ZoneConfig
{
    public string Domain { get; set; } = string.Empty;
    public SOAConfig SOA { get; set; } = new();
    public List<string> NSRecords { get; set; } = [];
    public List<RecordConfig> ARecords { get; set; } = [];
    public List<RecordConfig> AAAARecords { get; set; } = [];
}

public class SOAConfig
{
    public string MName { get; set; } = string.Empty;
    public string RName { get; set; } = string.Empty;
    public uint Serial { get; set; } = 2024032801;
    public uint Refresh { get; set; } = 3600;
    public uint Retry { get; set; } = 1800;
    public uint Expire { get; set; } = 604800;
    public uint Minimum { get; set; } = 3600;
}

public class RecordConfig
    
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public uint TTL { get; set; } = 3600;
}