namespace DNS.Packet.Enum;

/// <summary>
/// Enum for type constants in DNS.
/// </summary>
public enum DNSType : ushort
{
    /// <summary>
    /// Record for IPv4.
    /// </summary>
    A = 1,
    /// <summary>
    /// Authority record.
    /// </summary>
    NS = 2,
    /// <summary>
    /// Canonical name record.
    /// </summary>
    CNAME = 5,
    /// <summary>
    /// State of authority record.
    /// </summary>
    SOA = 6,
    /// <summary>
    /// Mail exchange record.
    /// </summary>
    MX = 15,
    /// <summary>
    /// Text record.
    /// </summary>
    TXT = 16,
    /// <summary>
    /// Record for IPv6
    /// </summary>
    AAAA = 28,
    /// <summary>
    /// EDNS0 Record.
    /// </summary>
    OPT = 41,
}