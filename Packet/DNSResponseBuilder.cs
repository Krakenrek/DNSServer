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
    }

    #endregion
    
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