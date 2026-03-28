namespace DNS.Packet.Serializable;

// ReSharper disable once InconsistentNaming
public interface IDNSSerializable
{
    void Serialize(Span<byte> buffer, ref int offset);
}