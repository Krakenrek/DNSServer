using System.Buffers.Binary;
using DNS.Packet.Enum;

namespace DNS.Packet.Serializable;

/// <summary>
/// Represents the Questions record of DNS packet.
/// </summary>
public readonly struct DNSQuestion : IDNSSerializable
{
    #region Properties

    /// <summary>
    /// Gets the record name of the question.
    /// </summary>
    public string Name { get; init; }
    /// <summary>
    /// Gets the record type of the question.
    /// </summary>
    public DNSType Type { get; init; }
    /// <summary>
    /// Gets the record class of the questions.
    /// </summary>
    public DNSClass Class { get; init; }

    #endregion

    #region Constructors

    /// <summary>
    /// Initializes a new instance of the DNSQuestion struct by parsing raw DNS packet data.
    /// </summary>
    /// <param name="raw">Raw byte representation.</param>
    /// <param name="offset">Offset from star of representation.</param>
    /// <exception cref="DnsParseException">Throws when can't read all fields properly.</exception>
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
        DNSHelper.WriteName(buffer, Name, ref offset, compressionTable);

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