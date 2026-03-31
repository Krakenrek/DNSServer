// ReSharper disable CollectionNeverUpdated.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable InconsistentNaming

using YamlDotNet.Serialization;

namespace DNS.Config.Record;

//TODO: Extra bytes at the end?
public class TXTRecord
{
    [YamlMember(Alias = "name")] public string? Name { get; set; }

    [YamlMember(Alias = "value")] public string? Value { get; set; }

    [YamlMember(Alias = "ttl")] public uint TTL { get; set; } = 3600;
}