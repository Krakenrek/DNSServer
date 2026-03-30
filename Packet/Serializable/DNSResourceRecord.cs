using System.Buffers.Binary;
using DNS.Packet.Enum;

namespace DNS.Packet.Serializable;

/// <summary>
/// Represents the general record of DNS packet.
/// </summary>
public readonly struct DNSResourceRecord : IDNSSerializable
{
    #region Properties

    /// <summary>
    /// Gets the record name.
    /// </summary>
    public string Name { get; init; }
    /// <summary>
    /// Gets the record type.
    /// </summary>
    public DNSType Type { get; init; }
    /// <summary>
    /// Gets the record class.
    /// </summary>
    public DNSClass Class { get; init; }
    
    /// <summary>
    /// Gets the record ttl.
    /// </summary>
    public uint TTL { get; init; }
    
    /// <summary>
    /// Gets the record data.
    /// </summary>
    public byte[] Data { get; init; }

    #endregion

    #region Constructors

    /// <summary>
    /// Initializes a new instance of the DNSResourceRecord struct by parsing raw DNS packet data.
    /// </summary>
    /// <param name="raw">Raw byte representation.</param>
    /// <param name="offset">Offset from star of representation.</param>
    /// <exception cref="DnsParseException">Throws when can't read all fields properly.</exception>
    public DNSResourceRecord(ReadOnlySpan<byte> raw, ref int offset)
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
                DnsParseException.ParseContext.ResourceRecord,
                nameof(Name),
                e.Message
            );
        }

        if (raw.Length - offset < 8)
        {
            offset = originalOffset;
            throw new DnsParseException(
                DnsParseException.ParseContext.ResourceRecord,
                nameof(DNSResourceRecord),
                "Raw data is too short"
            );
        }

        Type = (DNSType)BinaryPrimitives.ReadUInt16BigEndian(raw[offset..(offset + 2)]);
        Class = (DNSClass)BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 2)..(offset + 4)]);
        TTL = BinaryPrimitives.ReadUInt32BigEndian(raw[(offset + 4)..(offset + 8)]);
        var dataLength = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 8)..(offset + 10)]);

        if (raw.Length - offset < dataLength + 8)
        {
            offset = originalOffset;
            throw new DnsParseException(
                DnsParseException.ParseContext.ResourceRecord,
                nameof(Data),
                "Raw data is too short"
            );
        }

        offset += 10;

        Data = raw.Slice(offset, dataLength).ToArray();
        offset += dataLength;
    }

    /// <summary>
    /// Initializes a new instance of the DNSPacket struct with explicit values.
    /// </summary>
    /// <param name="name">Record name.</param>
    /// <param name="type">Record type.</param>
    /// <param name="cls">Record class.</param>
    /// <param name="ttl">Record ttl.</param>
    /// <param name="data">Record data.</param>
    public DNSResourceRecord(string name, DNSType type, DNSClass cls, uint ttl, byte[] data)
    {
        Name = name;
        Type = type;
        Class = cls;
        TTL = ttl;
        Data = data;
    }

    #endregion

    #region Serialization

    public void Serialize(Span<byte> buffer, ref int offset, Dictionary<string, int>? compressionTable = null)
    {
        DNSHelper.WriteName(buffer, Name, ref offset, compressionTable);

        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..(offset + 2)], (ushort)Type);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 2)..(offset + 4)], (ushort)Class);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + 4)..(offset + 8)], TTL);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 8)..(offset + 10)], (ushort)Data.Length);
        offset += 10;

        for (var i = 0; i < Data.Length; i++) buffer[offset + i] = Data[i];

        offset += Data.Length;
    }

    public int GetSize(Dictionary<string, int>? compressionTable = null)
    {
        return DNSHelper.GetNameLength(Name, compressionTable) +
               Data.Length +
               10;
    }

    #endregion
}