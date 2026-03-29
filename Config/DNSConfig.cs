// ReSharper disable CollectionNeverUpdated.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable InconsistentNaming

using YamlDotNet.Serialization;

namespace DNS.Config;

public class DNSConfig
{
    [YamlMember(Alias = "zones")]
    public List<DNSZone>? Zones { get; set; } = [];
}




