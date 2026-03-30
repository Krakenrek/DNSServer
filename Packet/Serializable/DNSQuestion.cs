using System.Buffers.Binary;
using DNS.Packet.Enum;

namespace DNS.Packet.Serializable;

public readonly struct DNSQuestion : IDNSSerializable
{
    #region Properties

    public string Name { get; init; }
    public DNSType Type { get; init; }
    public DNSClass Class { get; init; }

    #endregion

    #region Constructors

    public DNSQuestion(ReadOnlySpan<byte> raw, ref int offset)
    {
        var originalOffset = offset;

        try
        {
            Name = DNSHelper.ParseName(raw, ref offset);
        }
        catch (IndexOutOfRangeException e)
        {
            offset = originalOffset;
            throw new DnsParseException(
                DnsParseException.ParseContext.Question,
                nameof(Name),
                e.Message
            );
        }

        if (raw.Length - offset < 4)
        {
            offset = originalOffset;
            throw new DnsParseException(
                DnsParseException.ParseContext.Question,
                nameof(DNSQuestion),
                "Raw data is too short"
            );
        }

        Type = (DNSType)BinaryPrimitives.ReadUInt16BigEndian(raw[offset..(offset + 2)]);
        Class = (DNSClass)BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 2)..(offset + 4)]);

        offset += 4;
    }

    #endregion

    #region Serialization

    public void Serialize(Span<byte> buffer, ref int offset, Dictionary<string, int>? compressionTable = null)
    {
        DNSHelper.WriteName(buffer, Name, ref offset);

        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..(offset + 2)], (ushort)Type);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 2)..(offset + 4)], (ushort)Class);

        offset += 4;
    }

    public int GetSize(Dictionary<string, int>? compressionTable = null)
    {
        return DNSHelper.GetNameLength(Name, compressionTable) + 4;
    }

    #endregion
}