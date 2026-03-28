using System.Buffers.Binary;
using DNS.Packet.Enum;

namespace DNS.Packet.Serializable;

// ReSharper disable once InconsistentNaming
public readonly struct DNSResourceRecord : IDNSSerializable
{
    #region Properties
    // ReSharper disable MemberCanBePrivate.Global
    
    public string Name { get; init; }
    public DNSType Type { get; init; }
    public DNSClass Class { get; init; }
    
    // ReSharper disable once InconsistentNaming
    public uint TTL { get; init; }
    public byte[] Data { get; init; }

    // ReSharper restore MemberCanBePrivate.Global
    #endregion

    #region Constructors
    
    public DNSResourceRecord(ReadOnlySpan<byte> raw, ref int offset)
    {
        Name = DNSHelper.ParseName(raw, ref offset);
        Type = (DNSType) BinaryPrimitives.ReadUInt16BigEndian(raw[offset..(offset + 2)]);
        Class = (DNSClass) BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 2)..(offset + 4)]);
        TTL = BinaryPrimitives.ReadUInt32BigEndian(raw[(offset + 4)..(offset + 8)]);
        var dataLength = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 8)..(offset + 10)]);
        offset += 10;
        
        Data = raw.Slice(offset, dataLength).ToArray();
        offset += dataLength;
    }
    
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
    
    public void Serialize(Span<byte> buffer, ref int offset)
    {
        DNSHelper.WriteName(buffer, Name, ref offset);
        
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..(offset + 2)], (ushort) Type);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 2)..(offset + 4)], (ushort) Class);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + 4)..(offset + 8)], TTL);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 8)..(offset + 10)], (ushort) Data.Length);
        offset += 10;
        
        for (var i = 0; i < Data.Length; i++) buffer[offset + i] = Data[i];
        
        offset += Data.Length;
    }

    #endregion
}