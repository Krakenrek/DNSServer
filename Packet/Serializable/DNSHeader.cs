using System.Buffers.Binary;

namespace DNS.Packet.Serializable;

/// <summary>
/// Extension for nested enums in DNSHeader. 
/// </summary>
public static class DNSHeaderExtensions
{
    #region Flag Extensions

    extension(DNSHeader.Flag flag)
    {
        /// <summary>
        /// Determines whether the specified flag is set in the given flags value.
        /// </summary>
        /// <param name="flags">The raw flags value to test.</param>
        /// <returns>
        /// <c>true</c> if the flag is set (enabled); otherwise, <c>false</c>.
        /// </returns>
        public bool Test(ushort flags)
        {
            return (flag.Mask() & flags) != 0;
        }

        /// <summary>
        /// Sets the specified flag in the given flags value.
        /// </summary>
        /// <param name="flags">The raw flags value.</param>
        /// <returns>The updated flags value with the flag set.</returns>
        public ushort Set(ushort flags)
        {
            return (ushort)(flags | flag.Mask());
        }

        /// <summary>
        /// Clears the specified flag in the given flags value.
        /// </summary>
        /// <param name="flags">The raw flags value.</param>
        /// <returns>The updated flags value with the flag cleared.</returns>
        public ushort Clear(ushort flags)
        {
            return (ushort)(flags & ~flag.Mask());
        }

        /// <summary>
        /// Gets the bit mask (single bit set) for the given flag.
        /// </summary>
        /// <returns>The mask with the corresponding bit set, or 0 if flag unknown.</returns>
        private ushort Mask()
        {
            return flag switch
            {
                DNSHeader.Flag.Response => 1 << 15,
                DNSHeader.Flag.Authoritative => 1 << 10,
                DNSHeader.Flag.Truncated => 1 << 9,
                DNSHeader.Flag.RecursionDesired => 1 << 8,
                DNSHeader.Flag.RecursionAvailable => 1 << 7,
                _ => 0
            };
        }
    }

    #endregion

    #region ResponseCode Extension

    extension(DNSHeader.ResponseCode code)
    {
        /// <summary>
        /// Sets the response code in the given flags value.
        /// </summary>
        /// <param name="flags">The raw flags value.</param>
        /// <returns>
        /// The updated flags value with the Response Code set.
        /// </returns>
        public ushort Set(ushort flags)
        {
            flags &= ushort.MaxValue ^ 0xF;
            flags |= (ushort)((ushort)code & 0xF);
            return flags;
        }
    }

    #endregion

    #region OperationCode Extension

    extension(DNSHeader.OperationCode code)
    {
        /// <summary>
        /// Sets the operation code in the given flags value.
        /// </summary>
        /// <param name="flags">The raw flags value.</param>
        /// <returns>
        /// The updated flags value with the Response Code set.
        /// </returns>
        public ushort Set(ushort flags)
        {
            flags &= 0x87FF;
            flags |= (ushort)(((ushort)code & 0xF) << 11);
            return flags;
        }
    }

    #endregion
}

/// <summary>
/// Represents the header section of a DNS packet
/// </summary>
public readonly struct DNSHeader : IDNSSerializable
{
    #region Enums

    /// <summary>
    /// Enum for flags from DNS packet header.
    /// </summary>
    public enum Flag : ushort
    {
        /// <summary>Query/Response flag (QR). 0 = Query, 1 = Response.</summary>
        Response,

        /// <summary>Authoritative Answer flag (AA). 0 = Not authoritative, 1 = Authoritative.</summary>
        Authoritative,

        /// <summary>Truncation flag (TC). 0 = Not truncated, 1 = Truncated.</summary>
        Truncated,

        /// <summary>Recursion Desired flag (RD). 0 = Recursion isn't desired, 1 = Recursion is desired.</summary>
        RecursionDesired,

        /// <summary>Recursion Available flag (RA). 0 = Recursion isn't available, 1 = Recursion is available.</summary>
        RecursionAvailable
    }

    /// <summary>
    /// Enum for DNS operation codes from DNS header.
    /// </summary>
    public enum OperationCode : ushort
    {
        /// <summary>Standard query (QUERY).</summary>
        Query = 0,

        /// <summary>Server status request (STATUS).</summary>
        Status = 2,

        /// <summary>Notify message (NOTIFY).</summary>
        Notify = 4,

        /// <summary>Dynamic update (UPDATE).</summary>
        Update = 5
    }

    /// <summary>
    /// Enum for DNS response codes from DNS Header.
    /// </summary>
    public enum ResponseCode : ushort
    {
        /// <summary>DNS Query completed successfully (NOERROR).</summary>
        NoError = 0,

        /// <summary>DNS Query Format Error (FORMERR).</summary>
        FormatError = 1,

        /// <summary>Server failed to complete the DNS request (SERVFAIL).</summary>
        ServerFailed = 2,

        /// <summary>Domain name does not exist (NXDOMAIN).</summary>
        DomainDoesNotExist = 3,

        /// <summary>Function not implemented (NOTIMP).</summary>
        NotImplemented = 4,

        /// <summary>The server refused to answer for the query (REFUSED).</summary>
        Refused = 5,

        /// <summary>Name that should not exist, does exist (YXDOMAIN).</summary>
        DomainExist = 6,

        /// <summary>RRset that should not exist, does exist (XRRSET).</summary>
        ResourceRecordExist = 7,

        /// <summary>Server not authoritative for the zone (NOTAUTH).</summary>
        NotAuthorized = 8,

        /// <summary>Name not in zone (NOTZONE).</summary>
        NameNotInZone = 9
    }

    #endregion

    #region Properties

    /// <summary>
    /// Gets the 16-bit identifier assigned to the DNS query.
    /// This ID is copied from the query to the corresponding response.
    /// </summary>
    public ushort Id { get; init; }

    /// <summary>
    /// Gets the 16-bit flags field.
    /// </summary>
    public ushort Flags { get; init; }

    /// <summary>
    /// Gets the number of entries in the Question section.
    /// </summary>
    public ushort QuestionCount { get; init; }

    /// <summary>
    /// Gets the number of resource records in the Answer section.
    /// </summary>
    public ushort AnswerCount { get; init; }

    /// <summary>
    /// Gets the number of resource records in the Authority section.
    /// </summary>
    public ushort AuthorityCount { get; init; }

    /// <summary>
    /// Gets the number of resource records in the Additional section.
    /// </summary>
    public ushort AdditionalCount { get; init; }

    #endregion

    #region Flags

    /// <summary>
    /// Gets a value indicating whether this message is a response (QR).
    /// </summary>
    public bool IsResponse => Flag.Response.Test(Flags);

    /// <summary>
    /// Gets the operation code from the flags field.
    /// </summary>
    public OperationCode OpCode => GetOperationCode(Flags);

    /// <summary>
    /// Gets a value indicating whether the response is authoritative (AA).
    /// </summary>
    public bool IsAuthoritative => Flag.Authoritative.Test(Flags);

    /// <summary>
    /// Gets a value indicating whether the message was truncated (TC).
    /// </summary>
    public bool IsTruncated => Flag.Truncated.Test(Flags);

    /// <summary>
    /// Gets a value indicating whether recursion is desired (RD).
    /// </summary>
    public bool IsRecursionDesired => Flag.RecursionDesired.Test(Flags);

    /// <summary>
    /// Gets a value indicating whether recursion is available (RA).
    /// </summary>
    public bool IsRecursionAvailable => Flag.RecursionAvailable.Test(Flags);

    /// <summary>
    /// Gets the response code from the flags field.
    /// </summary>
    public ResponseCode RCode => GetResponseCode(Flags);

    #endregion

    #region Constructors

    /// <summary>
    /// Initializes a new instance of the DNSHeader struct by parsing raw DNS packet data.
    /// </summary>
    /// <param name="raw">Raw byte representation.</param>
    /// <param name="offset">Offset from star of representation.</param>
    /// <exception cref="DnsParseException">Throws when can't read all fields properly</exception>
    public DNSHeader(ReadOnlySpan<byte> raw, ref int offset)
    {
        if (raw.Length < 12)
            throw new DnsParseException(
                DnsParseException.ParseContext.Header,
                nameof(DNSHeader),
                "Raw data is too short."
            );

        Id = BinaryPrimitives.ReadUInt16BigEndian(raw[offset..(offset + 2)]);
        Flags = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 2)..(offset + 4)]);
        QuestionCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 4)..(offset + 6)]);
        AnswerCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 6)..(offset + 8)]);
        AuthorityCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 8)..(offset + 10)]);
        AdditionalCount = BinaryPrimitives.ReadUInt16BigEndian(raw[(offset + 10)..(offset + 12)]);

        offset += 12;
    }

    /// <summary>
    /// Initializes a new instance of the DNSHeader struct with explicit values.
    /// </summary>
    /// <param name="id">The DNS transaction identifier.</param>
    /// <param name="flags">The raw 16-bit flags value.</param>
    /// <param name="questionCount">Number of questions.</param>
    /// <param name="answerCount">Number of answers.</param>
    /// <param name="authorityCount">Number of authority records.</param>
    /// <param name="additionalCount">Number of additional records.</param>
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

    /// <summary>
    /// Extracts the response code from given flags value.
    /// </summary>
    /// <param name="flags">The raw flags value.</param>
    /// <returns>The <see cref="ResponseCode"/> value.</returns>
    public static ResponseCode GetResponseCode(ushort flags)
    {
        return (ResponseCode)(flags & 0xF);
    }

    /// <summary>
    /// Extracts the operation code from given flags value.
    /// </summary>
    /// <param name="flags">The raw flags value.</param>
    /// <returns>The <see cref="OperationCode"/> value.</returns>
    public static OperationCode GetOperationCode(ushort flags)
    {
        return (OperationCode)((flags >> 11) & 0x0F);
    }

    #endregion

    #region Serialization
    
    public void Serialize(Span<byte> buffer, ref int offset, Dictionary<string, int>? compressionTable = null)
    {
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..(offset + 2)], Id);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 2)..(offset + 4)], Flags);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 4)..(offset + 6)], QuestionCount);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 6)..(offset + 8)], AnswerCount);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 8)..(offset + 10)], AuthorityCount);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[(offset + 10)..(offset + 12)], AdditionalCount);
        offset += 12;
    }

    public int GetSize(Dictionary<string, int>? compressionTable = null)
    {
        return 12;
    }

    #endregion
}