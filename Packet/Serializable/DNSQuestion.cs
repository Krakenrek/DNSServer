using System.Buffers.Binary;
using DNS.Packet.Enum;

namespace DNS.Packet.Serializable;

// ReSharper disable once InconsistentNaming
public readonly struct DNSQuestion : IDNSSerializable
{
    #region Properties
    // ReSharper disable MemberCanBePrivate.Global
    
    public string Name { get; init; }
    public DNSType Type { get; init; }
    public DNSClass Class { get; init; }

    // ReSharper restore MemberCanBePrivate.Global
    #endregion

    #region Constructors
    
    public DNSQuestion(ReadOnlySpan<byte> raw, ref int size)
    {
        Name = DNSHelper.ParseName(raw, ref size);
        Type = (DNSType) BinaryPrimitives.ReadUInt16BigEndian(raw[size..(size + 2)]);
        Class = (DNSClass) BinaryPrimitives.ReadUInt16BigEndian(raw[(size + 2)..(size + 4)]);
        size += 4;
    }
    
    #endregion

    #region Serialization
    
    public void Serialize(Span<byte> buffer, ref int offset)
    {
        DNSHelper.WriteName(buffer, Name, ref offset);
        
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..(offset + 2)], (ushort) Type);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 2)..(offset + 4)], (ushort) Class);

        offset += 4;
    }

    #endregion
}
