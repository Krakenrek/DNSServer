// ReSharper disable CollectionNeverUpdated.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using YamlDotNet.Serialization;

namespace DNS;

public class DNSConfig
{
    [YamlMember(Alias = "zones")]
    public List<DNSZone>? Zones { get; set; } = [];
}

public class DNSZone
{
    [YamlMember(Alias = "domain")]
    public string? Domain { get; set; }
    [YamlMember(Alias = "soa")]
    public SOARecord? Soa { get; set; }
    [YamlMember(Alias = "ns_records")]
    public List<string>? NSRecords { get; set; } = [];
    [YamlMember(Alias = "a_records")]
    public List<ARecord>? ARecords { get; set; } = [];
    [YamlMember(Alias = "aaaa_records")]
    public List<AAAARecord>? AAAARecords { get; set; } = [];
}

public class SOARecord
{
    [YamlMember(Alias = "m_name")]
    public string? MName { get; set; }
    [YamlMember(Alias = "r_name")]
    public string? RName { get; set; }
    [YamlMember(Alias = "serial")]
    public uint? Serial { get; set; }
    [YamlMember(Alias = "refresh")]
    public uint? Refresh { get; set; }
    [YamlMember(Alias = "retry")]
    public uint? Retry { get; set; }
    [YamlMember(Alias = "expire")]
    public uint? Expire { get; set; }
    [YamlMember(Alias = "minimum")]
    public uint? Minimum { get; set; }
}

public class ARecord
{
    [YamlMember(Alias = "name")]
    public string? Name { get; set; }
    
    [YamlMember(Alias = "value")]
    public string? Value { get; set; }
    
    [YamlMember(Alias = "ttl")]
    public uint TTL { get; set; } = 3600;
}

public class AAAARecord
{
    [YamlMember(Alias = "name")]
    public string? Name { get; set; }
    
    [YamlMember(Alias = "value")]
    public string? Value { get; set; }
    
    [YamlMember(Alias = "ttl")]
    public uint TTL { get; set; } = 3600;
}