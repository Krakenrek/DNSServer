using DNS.Packet.Enum;
using DNS.Packet.Serializable;

namespace DNS.Packet;

// ReSharper disable once InconsistentNaming
public class DNSResponseBuilder
{
    #region Properties

    private ushort Id { get; set; }
    private ushort Flags { get; set; }
    
    private List<DNSQuestion> Questions { get; } = [];
    private List<DNSResourceRecord> Answers { get; } = [];
    private List<DNSResourceRecord> Authority { get; } = [];
    private List<DNSResourceRecord> Additional { get; } = [];

    #endregion

    #region Constructors

    public DNSResponseBuilder(DNSPacket query)
    {
        Id = query.Header.Id;
        Flags = DNSHeader.Flag.Response.Set(query.Header.Flags);
        
        Questions.AddRange(query.Questions);
        AddEDNSIfPresent(query);
    }

    public DNSResponseBuilder(DNSHeader header)
    {
        Id = header.Id;
        Flags = header.Flags;
    }

    #endregion

    #region Static Methods

    public static DNSResponseBuilder fromOnlyHeader(Span<byte> raw)
    {
        var offset = 0;
        return new DNSResponseBuilder(new DNSHeader(raw, ref offset));
    }

    #endregion
    
    private void AddEDNSIfPresent(DNSPacket query)
    {
        const ushort fallback = 1232;
        const ushort upperBound = 4096;
        
        var opt = query.Additional
            .Select(record => new DNSResourceRecord?(record))
            .FirstOrDefault(record => record!.Value.Type == DNSType.OPT);
        if (opt == null) return;
        var record = opt!.Value;
        
        var udpSize = (ushort) record.Class == 0 ? fallback : Math.Max(upperBound, (ushort) record.Class);
        AddAdditional(new DNSResourceRecord(
            ".", 
            DNSType.OPT, 
            (DNSClass) udpSize,
            0,
            []
            )
        );
    }
    
    
    #region Flag Methods
    
    public DNSResponseBuilder SetAuthoritative(bool authoritative = true)
    {
        Flags = authoritative ? DNSHeader.Flag.Authoritative.Set(Flags) : DNSHeader.Flag.Authoritative.Clear(Flags);
        return this;
    }
    
    public DNSResponseBuilder SetRecursionAvailable(bool recursion = true)
    {
        Flags = recursion ? DNSHeader.Flag.RecursionAvailable.Set(Flags) : DNSHeader.Flag.RecursionAvailable.Clear(Flags);
        return this;
    }

    public DNSResponseBuilder SetTruncated(bool truncated = true)
    {
        Flags = truncated ? DNSHeader.Flag.Truncated.Set(Flags) : DNSHeader.Flag.Truncated.Clear(Flags);
        return this;
    }
    
    public DNSResponseBuilder SetResponseCode(DNSHeader.ResponseCode responseCode)
    {
        Flags = responseCode.Set(Flags);
        return this;
    }

    #endregion
    
    #region Resource Record Methods
    
    public DNSResponseBuilder AddAnswer(DNSResourceRecord answer)
    {
        Answers.Add(answer);
        return this;
    }
    
    public DNSResponseBuilder AddAnswers(IEnumerable<DNSResourceRecord> answers)
    {
        Answers.AddRange(answers);
        return this;
    }
    
    public DNSResponseBuilder AddAuthority(DNSResourceRecord authority)
    {
        Authority.Add(authority);
        return this;
    }
    
    public DNSResponseBuilder AddAuthorities(IEnumerable<DNSResourceRecord> authorities)
    {
        Authority.AddRange(authorities);
        return this;
    }
    
    public DNSResponseBuilder AddAdditional(DNSResourceRecord additional)
    {
        Additional.Add(additional);
        return this;
    }
    
    public DNSResponseBuilder AddAdditional(IEnumerable<DNSResourceRecord> additional)
    {
        Additional.AddRange(additional);
        return this;
    }

    #endregion

    #region Build Method
    
    public DNSPacket Build()
    {
        return new DNSPacket(
            new DNSHeader(
                Id, 
                Flags, 
                (ushort) Questions.Count, 
                (ushort) Answers.Count, 
                (ushort) Authority.Count, 
                (ushort) Additional.Count
                ),
            Questions,
            Answers,
            Authority,
            Additional
            );
    }

    #endregion
}