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
        const int ptrOffset = 0x3F;

        var nameBuilder = new StringBuilder();
        var originalOffset = 0;
        var jumped = false;
        var jumpCount = 0;

        while (true)
        {
            if (jumpCount > jumpThreshold)
                throw new Exception("Too many DNS pointers (cycle?)");

            var length = raw[offset];
            
            if ((length & ptrMarker) == ptrMarker)
            {
                var pointerOffset = ((length & ptrOffset) << 8) | raw[offset + 1];

                if (!jumped)
                {
                    originalOffset = offset + 2;
                    jumped = true;
                }

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
            
            var label = Encoding.ASCII.GetString(raw.Slice(offset, length));
            nameBuilder.Append(label).Append('.');
            offset += length;
        }

        if (jumped)
        {
            offset = originalOffset;
        }

        return nameBuilder.ToString().TrimEnd('.');
    }
    
    public static void WriteName(Span<byte> buffer, string name, ref int offset)
    {
        if (string.IsNullOrWhiteSpace(name) || name == ".")
        {
            buffer[offset++] = 0;
            return;
        }
        
        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);

        foreach (var label in labels)
        {
            if (label.Length > 63)
                throw new ArgumentException($"Label too long (max 63 bytes): {label}");
            
            buffer[offset++] = (byte)label.Length;
            
            int written = Encoding.ASCII.GetBytes(label, buffer.Slice(offset));
            offset += written;
        }
        
        buffer[offset++] = 0;
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