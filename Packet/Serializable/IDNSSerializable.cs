namespace DNS.Packet.Serializable;

/// <summary>
/// Interface for something that can be written to dns packets as byte representation.
/// </summary>
public interface IDNSSerializable
{
    /// <summary>
    /// Writes to given buffer starting from offset.
    /// Modifies offset after writing
    /// Uses compression table, populates it.
    /// </summary>
    /// <param name="buffer">Buffer to write to.</param>
    /// <param name="offset">Offset from buffer start.</param>
    /// <param name="compressionTable">Table of suffixes for compression. Can be null.</param>
    void Serialize(Span<byte> buffer, ref int offset, Dictionary<string, int>? compressionTable = null);
    
    /// <summary>
    /// Precalculates size of serialized object.
    /// Populates compression table.
    /// </summary>
    /// <param name="compressionTable">Table of suffixes for compression. Can be null.</param>
    /// <returns></returns>
    int GetSize(Dictionary<string, int>? compressionTable = null);
}