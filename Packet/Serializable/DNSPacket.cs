namespace DNS.Packet.Serializable;

// ReSharper disable once InconsistentNaming
public class DNSPacket : IDNSSerializable
{
    #region Properties
    // ReSharper disable MemberCanBePrivate.Global
    
    public DNSHeader Header { get; set; }
    
    public DNSQuestion[] Questions { get; }
    public DNSResourceRecord[] Answers { get; }
    public DNSResourceRecord[] Authority { get; }
    public DNSResourceRecord[] Additional { get; }

    // ReSharper restore MemberCanBePrivate.Global
    #endregion

    #region Constructors
    
    public DNSPacket(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 12)
            throw new ArgumentException("DNS packet must be at least 12 bytes.");

        var offset = 0;
        
        Header = new DNSHeader(raw, ref offset);

        Questions = new DNSQuestion[Header.QuestionCount];
        Answers = new DNSResourceRecord[Header.AnswerCount];
        Authority = new DNSResourceRecord[Header.AuthorityCount];
        Additional = new DNSResourceRecord[Header.AdditionalCount];
        
        for (var i = 0; i < Header.QuestionCount; i++) 
            Questions[i] = new DNSQuestion(raw, ref offset);
        
        for (var i = 0; i < Header.AnswerCount; i++)
            Answers[i] = new DNSResourceRecord(raw, ref offset);

        for (var i = 0; i < Header.AuthorityCount; i++)
            Authority[i] = new DNSResourceRecord(raw, ref offset);
        
        for (var i = 0; i < Header.AdditionalCount; i++)
            Additional[i] = new DNSResourceRecord(raw, ref offset);
    }

    public DNSPacket(
        DNSHeader header,
        IEnumerable<DNSQuestion> questions,
        IEnumerable<DNSResourceRecord> answers,
        IEnumerable<DNSResourceRecord> authority,
        IEnumerable<DNSResourceRecord> additional)
    {
        Header = header;
        Questions = questions.ToArray();
        Answers = answers.ToArray();
        Authority = authority.ToArray();
        Additional = additional.ToArray();
    }

    #endregion

    #region Serialization
    
    public void Serialize(Span<byte> buffer, ref int offset)
    {
        Header.Serialize(buffer, ref offset);
        
        foreach (var question in Questions) 
            question.Serialize(buffer, ref offset);
        foreach (var answer in Answers)
            answer.Serialize(buffer, ref offset);
        foreach (var authority in Authority)
            authority.Serialize(buffer, ref offset);
        foreach (var additional in Additional)
            additional.Serialize(buffer, ref offset);
    }

    #endregion


}