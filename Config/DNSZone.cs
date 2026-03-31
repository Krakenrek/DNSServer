// ReSharper disable CollectionNeverUpdated.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable InconsistentNaming

using DNS.Config.Record;
using YamlDotNet.Serialization;

namespace DNS.Config;

public class DNSZone
{
    [YamlMember(Alias = "domain")] public string? Domain { get; set; }

    [YamlMember(Alias = "soa")] public SOARecord? Soa { get; set; }

    [YamlMember(Alias = "ns_records")] public List<string>? NSRecords { get; set; } = [];

    [YamlMember(Alias = "a_records")] public List<ARecord>? ARecords { get; set; } = [];

    [YamlMember(Alias = "aaaa_records")] public List<AAAARecord>? AAAARecords { get; set; } = [];

    [YamlMember(Alias = "cname_records")] public List<CNameRecord>? CNameRecords { get; set; } = [];

    [YamlMember(Alias = "mx_records")] public List<MXRecord>? MXRecords { get; set; } = [];

    [YamlMember(Alias = "txt_records")] public List<TXTRecord>? TXTRecords { get; set; } = [];
}