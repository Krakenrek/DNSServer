using System.Buffers.Binary;

namespace DNS.Packet;

using System;
using System.Text;

// ReSharper disable once InconsistentNaming
public static class DNSHelper
{
    #region Static Methods

    public static string ParseName(ReadOnlySpan<byte> raw, ref int offset)
    {
        const int jumpThreshold = 10;
        const int ptrMarker = 0xC0;
        const int ptrOffsetMask = 0x3F;

        var nameBuilder = new StringBuilder();
        int? originalOffset = null;
        var jumpCount = 0;

        while (true)
        {
            if (jumpCount > jumpThreshold)
                throw new Exception("Too many DNS pointers (cycle?)");

            if (offset >= raw.Length)
                throw new IndexOutOfRangeException("Unexpected end of buffer while reading label length.");

            var length = raw[offset];

            if ((length & ptrMarker) == ptrMarker)
            {
                if (offset + 1 >= raw.Length)
                    throw new IndexOutOfRangeException("Unexpected end of buffer while reading pointer offset.");

                var pointerOffset = ((length & ptrOffsetMask) << 8) | raw[offset + 1];

                originalOffset ??= offset + 2;

                if (pointerOffset >= raw.Length)
                    throw new IndexOutOfRangeException("DNS pointer points outside the buffer.");

                offset = pointerOffset;
                jumpCount++;
                continue;
            }

            if (length == 0)
            {
                offset++;
                break;
            }

            offset++;

            if (offset + length > raw.Length)
                throw new IndexOutOfRangeException($"Buffer too small to read label of length {length}.");

            var label = Encoding.ASCII.GetString(raw.Slice(offset, length));
            nameBuilder.Append(label).Append('.');

            offset += length;
        }

        if (originalOffset.HasValue)
        {
            offset = originalOffset.Value;
        }

        return nameBuilder.ToString().TrimEnd('.');
    }


    public static void WriteName(Span<byte> buffer, string name, ref int offset, Dictionary<string, int>? compressionTable = null)
    {
        const int maxPointerOffset = 0x4000;
        const ushort pointerPrefix = 0xC000;

        if (string.IsNullOrWhiteSpace(name) || name == ".")
        {
            if (offset >= buffer.Length)
                throw new ArgumentException("Insufficient space in buffer for name.");

            buffer[offset++] = 0;
            return;
        }

        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);

        var i = 0;
        while (true)
        {
            if (i >= labels.Length)
            {
                if (offset >= buffer.Length)
                    throw new ArgumentException("Insufficient space in buffer for name terminator.");

                buffer[offset++] = 0;
                break;
            }

            if (compressionTable != null)
            {
                var suffix = string.Join(".", labels, i, labels.Length - i);

                if (compressionTable.TryGetValue(suffix, out var knownOffset) && knownOffset < maxPointerOffset)
                {
                    if (offset + 2 > buffer.Length)
                        throw new ArgumentException("Insufficient space in buffer for name compression pointer.");

                    var pointer = (ushort)(pointerPrefix | knownOffset);
                    buffer[offset++] = (byte)(pointer >> 8);
                    buffer[offset++] = (byte)pointer;
                    break;
                }

                compressionTable[suffix] = offset;
            }

            var label = labels[i];
            
            if (label.Length > 63)
                throw new ArgumentException($"Label too long (max 63 bytes): {label}");

            if (offset >= buffer.Length)
                throw new ArgumentException("Insufficient space in buffer for DNS label length byte.");

            buffer[offset++] = (byte)label.Length;

            if (offset + label.Length > buffer.Length) 
                throw new ArgumentException("Insufficient space in buffer for DNS label data.");

            var bytesWritten = Encoding.ASCII.GetBytes(label, buffer[offset..]);
            offset += bytesWritten;

            i++;
        }
    }
    
    public static int GetNameLength(string name, Dictionary<string, int>? compressionTable = null, int startingOffset = 0)
    {
        const int maxPointerOffset = 0x4000;

        if (string.IsNullOrWhiteSpace(name) || name == ".") return 1;

        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);

        var length = 0;
        var i = 0;
        var virtualOffset = startingOffset;

        while (true)
        {
            if (i >= labels.Length)
            {
                length += 1;
                break;
            }

            if (compressionTable != null)
            {
                var suffix = string.Join(".", labels, i, labels.Length - i);

                if (compressionTable.TryGetValue(suffix, out var knownOffset) && knownOffset < maxPointerOffset)
                {
                    length += 2;
                    break;
                }

                compressionTable[suffix] = virtualOffset;
            }

            var label = labels[i];
            if (label.Length > 63)
                throw new ArgumentException($"Label too long (max 63 bytes): {label}");

            length += 1 + label.Length;

            if (compressionTable != null) virtualOffset += 1 + label.Length;

            i++;
        }

        return length;
    }
    
    // ReSharper disable once InconsistentNaming
    public static byte[] CreateSOARData(
        string mname, 
        string rname, 
        uint serial, 
        uint refresh, 
        uint retry, 
        uint expire, 
        uint minimum)
    {
        Span<byte> buffer = stackalloc byte[512];
        var offset = 0;
        
        WriteName(buffer, mname, ref offset);
        WriteName(buffer, rname, ref offset);
        
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