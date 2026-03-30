namespace DNS.Packet;

public class DnsParseException(DnsParseException.ParseContext context, string field, string message) : Exception(message)
{
    public enum ParseContext
    {
        Header,
        Question,
        ResourceRecord
    }

    public string FailedField { get; } = field;
    
    public ParseContext Context { get; } = context;
}