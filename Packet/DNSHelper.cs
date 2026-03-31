using System.Buffers.Binary;

namespace DNS.Packet;

using System;
using System.Text;

/// <summary>
/// Holder of DNS helper functions.
/// </summary>
public static class DNSHelper
{
    #region Static Methods

    /// <summary>
    /// Parses the qname from rae representation.
    /// Updates offset.
    /// </summary>
    /// <param name="raw">Raw representation of name.</param>
    /// <returns></returns>
    public static string ParseName(ReadOnlySpan<byte> raw)
    {
        var offset = 0;
        return ParseName(raw, ref offset);
    }

    public static void WriteName(Span<byte> buffer, string str)
    {
        var offset = 0;
        WriteName(buffer, str, ref offset);
    }
    
    /// <summary>
    /// Parses the qname from rae representation.
    /// Updates offset.
    /// </summary>
    /// <param name="raw">Raw representation of name.</param>
    /// <param name="offset">Offset from raw data start.</param>
    /// <returns>Parsed name.</returns>
    /// <exception cref="IndexOutOfRangeException">Thrown when raw representation is broken (achieved OOB).</exception>
    /// <exception cref="Exception">Thrown when cycle is encountered (too many jumps).</exception>
    public static string ParseName(ReadOnlySpan<byte> raw, ref int offset)
    {
        const int jumpThreshold = 25;
        const int ptrMarker = 0xC0;
        const int ptrOffsetMask = 0x3F;

        var nameBuilder = new StringBuilder();
        int? originalOffset = null;
        var jumpCount = 0;

        while (true)
        {
            if (offset >= raw.Length)
                throw new IndexOutOfRangeException("Unexpected end of buffer while reading label length.");

            var length = raw[offset];

            if ((length & ptrMarker) == ptrMarker)
            {
                if (jumpCount++ > jumpThreshold)
                    throw new Exception("Too many DNS pointers (cycle?)");

                if (offset + 1 >= raw.Length)
                    throw new IndexOutOfRangeException("Unexpected end of buffer while reading pointer offset.");

                var pointerOffset = ((length & ptrOffsetMask) << 8) | raw[offset + 1];
                originalOffset ??= offset + 2;

                if (pointerOffset >= raw.Length)
                    throw new IndexOutOfRangeException("DNS pointer points outside the buffer.");

                offset = pointerOffset;
                continue;
            }

            if (length == 0)
            {
                offset++;
                break;
            }

            if (length > 63)
                throw new Exception("DNS label length exceeds 63 bytes.");

            offset++;

            if (offset + length > raw.Length)
                throw new IndexOutOfRangeException($"Buffer too small to read label of length {length}.");

            var label = Encoding.ASCII.GetString(raw.Slice(offset, length));
            nameBuilder.Append(label).Append('.');

            offset += length;
        }

        if (originalOffset.HasValue) offset = originalOffset.Value;

        return nameBuilder.ToString().TrimEnd('.');
    }

    /// <summary>
    /// Writes qname to given buffer
    /// Updates offset.
    /// Populates compression table.
    /// </summary>
    /// <param name="buffer">The buffer.</param>
    /// <param name="name">String to write.</param>
    /// <param name="offset">Offset from buffer start.</param>
    /// <param name="compressionTable">Suffix table for compression.</param>
    /// <exception cref="ArgumentException">Thrown when couldn't convert.</exception>
    public static void WriteName(Span<byte> buffer, string name, ref int offset,
        Dictionary<string, int>? compressionTable = null)
    {
        const int maxPointerOffset = 0x3FFF;
        const ushort pointerPrefix = 0xC000;

        if (string.IsNullOrWhiteSpace(name) || name == ".")
        {
            if (offset >= buffer.Length)
                throw new ArgumentException("Insufficient space in buffer.");

            buffer[offset++] = 0;
            return;
        }

        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);

        for (var i = 0; i < labels.Length; i++)
        {
            if (compressionTable != null)
            {
                var suffix = string.Join(".", labels, i, labels.Length - i).ToLowerInvariant();

                if (compressionTable.TryGetValue(suffix, out var knownOffset) && knownOffset <= maxPointerOffset &&
                    knownOffset < offset)
                {
                    if (offset + 2 > buffer.Length)
                        throw new ArgumentException("Insufficient space for pointer.");

                    var pointer = (ushort)(pointerPrefix | (ushort) knownOffset);
                    buffer[offset++] = (byte)(pointer >> 8);
                    buffer[offset++] = (byte)(pointer & 0xFF);
                    return;
                }

                compressionTable[suffix] = offset;
            }

            var label = labels[i];
            if (label.Length > 63)
                throw new ArgumentException($"Label too long: {label}");

            if (offset + 1 + label.Length > buffer.Length)
                throw new ArgumentException("Insufficient space for label.");

            buffer[offset++] = (byte)label.Length;
            offset += Encoding.ASCII.GetBytes(label, buffer[offset..]);
        }

        if (offset >= buffer.Length)
            throw new ArgumentException("Insufficient space for terminator.");

        buffer[offset++] = 0;
    }

    /// <summary>
    /// Get qname byte representation length in bytes.
    /// Populates compression table.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="compressionTable">Suffix table for compression.</param>
    /// <param name="startingOffset">Offset from string start.</param>
    /// <returns>Length of the byte representation of given string,</returns>
    /// <exception cref="ArgumentException">Thrown when name is too long.</exception>
    public static int GetNameLength(string name, Dictionary<string, int>? compressionTable = null,
        int startingOffset = 0)
    {
        const int maxPointerOffset = 0x3FFF;

        if (string.IsNullOrWhiteSpace(name) || name == ".") return 1;

        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var totalLength = 0;
        var currentVirtualOffset = startingOffset;

        for (var i = 0; i < labels.Length; i++)
        {
            if (compressionTable != null)
            {
                var suffix = string.Join(".", labels, i, labels.Length - i).ToLowerInvariant();

                if (compressionTable.TryGetValue(suffix, out var knownOffset) && knownOffset <= maxPointerOffset &&
                    knownOffset < currentVirtualOffset) return totalLength + 2;

                compressionTable[suffix] = currentVirtualOffset;
            }

            var labelLength = labels[i].Length;
            if (labelLength > 63)
                throw new ArgumentException($"Label too long: {labels[i]}");

            var segmentLength = 1 + labelLength;
            totalLength += segmentLength;
            currentVirtualOffset += segmentLength;
        }

        return totalLength + 1;
    }

    /// <summary>
    /// Generates SOA data.
    /// </summary>
    /// <param name="mName">MName.</param>
    /// <param name="rName">RName.</param>
    /// <param name="serial">Serial.</param>
    /// <param name="refresh">Refresh.</param>
    /// <param name="retry">Retry.</param>
    /// <param name="expire">Expire.</param>
    /// <param name="minimum">Minimum.</param>
    /// <returns>SOA data.</returns>
    public static byte[] CreateSOAData(
        string mName,
        string rName,
        uint serial,
        uint refresh,
        uint retry,
        uint expire,
        uint minimum)
    {
        Span<byte> buffer = stackalloc byte[512];
        var offset = 0;

        WriteName(buffer, mName, ref offset);
        WriteName(buffer, rName, ref offset);

        BinaryPrimitives.WriteUInt32BigEndian(buffer[offset..(offset + 4)], serial);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + 4)..(offset + 8)], refresh);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + 8)..(offset + 12)], retry);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + 12)..(offset + 16)], expire);
        BinaryPrimitives.WriteUInt32BigEndian(buffer[(offset + 16)..(offset + 20)], minimum);

        offset += 20;

        var result = new byte[offset];

        buffer[..offset].CopyTo(result);

        return result;
    }

    /// <summary>
    /// Generates name data.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <returns>Data of the given name.</returns>
    public static byte[] CreateNameRData(string name)
    {
        const int maxNameLength = 256;

        if (string.IsNullOrWhiteSpace(name)) return [];

        Span<byte> buffer = stackalloc byte[maxNameLength];
        var offset = 0;

        WriteName(buffer, name, ref offset);

        var result = new byte[offset];
        buffer[..offset].CopyTo(result);

        return result;
    }

    /// <summary>
    /// Get full qname.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <param name="zoneDomain">The domain.</param>
    /// <returns>Full qname.</returns>
    public static string GetFullQName(string name, string zoneDomain)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Equals(zoneDomain, StringComparison.OrdinalIgnoreCase))
            return zoneDomain;

        if (name.EndsWith("." + zoneDomain, StringComparison.OrdinalIgnoreCase))
            return name;

        return name + "." + zoneDomain;
    }

    #endregion
}