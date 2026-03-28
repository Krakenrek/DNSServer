using System.Buffers.Binary;

namespace DNS.Packet.Serializable;

// ReSharper disable once InconsistentNaming
public static class DNSHeaderExtensions
{
    #region Flag Extensions
    
    extension(DNSHeader.Flag flag)
    {
        public bool Test(ushort flags)
        {
            return (Mask(flag) & flags) != 0;
        }
        
        public ushort Set(ushort flags)
        {
            return (ushort)(Mask(flag) | flags);
        }
        
        public ushort Clear(ushort flags)
        {
            return (ushort)(Mask(flag) & ~flags);
        }
    }

    private static ushort Mask(DNSHeader.Flag flag) => flag switch
    {
        DNSHeader.Flag.Response => 1 << 15,
        DNSHeader.Flag.Authoritative => 1 << 11,
        DNSHeader.Flag.Truncated => 1 << 10,
        DNSHeader.Flag.RecursionDesired => 1 << 9,
        DNSHeader.Flag.RecursionAvailable => 1 << 8,
        _ => 0
    };

    #endregion

    #region ResponseCode Extension
    
    public static ushort Set(this DNSHeader.ResponseCode code, ushort flags)
    {
        flags &= ushort.MaxValue ^ 0xF;
        flags |= (ushort)((ushort)code & 0xF);
        return flags;
    }

    #endregion

    #region OperationCode Extension
    
    public static ushort Set(this DNSHeader.OperationCode code, ushort flags)
    {
        flags &= 0x87FF;
        flags |= (ushort)(((ushort)code & 0xF) << 11);
        return flags;
    }

    #endregion
}

// ReSharper disable once InconsistentNaming
public readonly struct DNSHeader : IDNSSerializable
{
    #region Enums

    public enum Flag : ushort
    {
        Response,
        Authoritative,
        Truncated,
        RecursionDesired,
        RecursionAvailable
    }

    public enum OperationCode : ushort
    {
        Query = 0,
        Status = 2,
        Notify = 4,
        Update = 5
    }

    public enum ResponseCode : ushort
    {
        NoError = 0,
        FormatError = 1,
        ServerFailed = 2,
        DomainNotExist = 3,
        NotImplemented = 4,
        Refused = 5,
        DomainExist = 6,
        ResourceRecordExist = 7,
        NotAuthorized = 8,
        NameNotInZone = 9
    }

    #endregion

    #region Properties
    
    public ushort Id { get; init; }
    
    public ushort Flags { get; init; }
    
    public ushort QuestionCount { get; init; }
    
    public ushort AnswerCount { get; init; }
    
    public ushort AuthorityCount { get; init; }
    
    public ushort AdditionalCount { get; init; }

    #endregion

    #region Flags
    
    public bool IsResponse => Flag.Response.Test(Flags);
    
    public OperationCode OpCode => GetOperationCode(Flags);
    
    public bool IsAuthoritative => Flag.Authoritative.Test(Flags);
    
    public bool IsTruncated => Flag.Truncated.Test(Flags);
    
    public bool RecursionDesired => Flag.RecursionDesired.Test(Flags);
    
    public bool RecursionAvailable => Flag.RecursionAvailable.Test(Flags);
    
    public ResponseCode RCode => GetResponseCode(Flags);

    #endregion

    #region Constructors
    
    public DNSHeader(ReadOnlySpan<byte> raw, ref int offset)
    {
        if (raw.Length < 12)
            throw new ArgumentException("DNS Header must be 12 bytes.");

        Id = BinaryPrimitives.ReadUInt16BigEndian(raw[offset..(offset + 2)]);
        Flags = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 2)..(offset + 4)]);
        QuestionCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 4)..(offset + 6)]);
        AnswerCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 6)..(offset + 8)]);
        AuthorityCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 8)..(offset + 10)]);
        AdditionalCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 10)..(offset + 12)]);
        offset += 12;
    }

    public DNSHeader(
        ushort id,
        ushort flags,
        ushort questionCount, 
        ushort answerCount, 
        ushort authorityCount,
        ushort additionalCount
        )
    {
        Id = id;
        Flags = flags;
        QuestionCount = questionCount;
        AnswerCount = answerCount;
        AuthorityCount = authorityCount;
        AdditionalCount = additionalCount;
    }
    
    #endregion

    #region Static Methods
    
    public static ResponseCode GetResponseCode(ushort flags)
    {
        return (ResponseCode) (flags & 0xF);
    }
    
    public static OperationCode GetOperationCode(ushort flags)
    {
        return (OperationCode) ((flags >> 11) & 0x0F);
    }

    #endregion

    #region Serialization
    
    public void Serialize(Span<byte> buffer, ref int offset)
    {
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..(offset + 2)], Id);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 2)..(offset + 4)], Flags);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 4)..(offset + 6)], QuestionCount);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 6)..(offset + 8)], AnswerCount);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 8)..(offset + 10)], AuthorityCount);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 10)..(offset + 12)], AdditionalCount);
        offset += 12;
    }

    #endregion
}