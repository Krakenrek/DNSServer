namespace DNS.Packet;

/// <summary>
/// Simple representation of error when parsing DNS packet.
/// </summary>
/// <param name="context">Parsing context.</param>
/// <param name="field">Field which failed to be populated</param>
/// <param name="message">Exception message.</param>
public class DnsParseException(DnsParseException.ParseContext context, string field, string message)
    : Exception(message)
{
    #region Enum

    /// <summary>
    /// Enum representation of parsing context.
    /// </summary>
    public enum ParseContext
    {
        Header,
        Question,
        ResourceRecord
    }

    #endregion

    #region Properties

    /// <summary>
    /// Gets field which failed to be populated.
    /// </summary>
    public string FailedField { get; } = field;

    /// <summary>
    /// Gets context of exception.
    /// </summary>
    public ParseContext Context { get; } = context;

    #endregion
    

}