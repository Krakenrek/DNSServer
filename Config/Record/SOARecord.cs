// ReSharper disable CollectionNeverUpdated.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable InconsistentNaming

using YamlDotNet.Serialization;

namespace DNS.Config.Record;

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
