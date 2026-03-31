// ReSharper disable CollectionNeverUpdated.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable InconsistentNaming

using YamlDotNet.Serialization;

namespace DNS.Config.Record;

public class MXRecord
{
    [YamlMember(Alias = "name")] public string? Name { get; set; }

    [YamlMember(Alias = "priority")] public short? Priority {get; set; } 

    [YamlMember(Alias = "value")] public string? Value { get; set; }

    [YamlMember(Alias = "ttl")] public uint TTL { get; set; } = 3600;
}