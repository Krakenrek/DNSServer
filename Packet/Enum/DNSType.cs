namespace DNS.Packet.Enum;

/// <summary>
/// Enum for type constants in DNS.
/// </summary>
public enum DNSType : ushort
{
    A = 1,
    NS = 2,
    SOA = 6,
    AAAA = 28,
    OPT = 41
}