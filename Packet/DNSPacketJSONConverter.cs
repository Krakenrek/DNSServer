using System.Text.Json;
using System.Text.Json.Serialization;
using DNS.Packet.Serializable;

namespace DNS.Packet;

public class DNSPacketJsonConverter : JsonConverter<DNSPacket>
{
    public override DNSPacket Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject) throw new JsonException();

        DNSHeader header = default;
        List<DNSQuestion> questions = [];
        List<DNSResourceRecord> answers = [];
        List<DNSResourceRecord> authority = [];
        List<DNSResourceRecord> additional = [];

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject) break;

            var propertyName = reader.GetString();
            reader.Read();

            switch (propertyName)
            {
                case "Header":
                    header = JsonSerializer.Deserialize<DNSHeader>(ref reader, options);
                    break;
                case "Questions":
                    questions = JsonSerializer.Deserialize<List<DNSQuestion>>(ref reader, options) ??
                                new List<DNSQuestion>();
                    break;
                case "Answers":
                    answers = JsonSerializer.Deserialize<List<DNSResourceRecord>>(ref reader, options) ??
                              new List<DNSResourceRecord>();
                    break;
                case "Authority":
                    authority = JsonSerializer.Deserialize<List<DNSResourceRecord>>(ref reader, options) ??
                                new List<DNSResourceRecord>();
                    break;
                case "Additional":
                    additional = JsonSerializer.Deserialize<List<DNSResourceRecord>>(ref reader, options) ??
                                 new List<DNSResourceRecord>();
                    break;
            }
        }

        return new DNSPacket(header, questions, answers, authority, additional);
    }

    public override void Write(Utf8JsonWriter writer, DNSPacket value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        writer.WritePropertyName("Header");
        SerializeHeader(writer, value.Header, options);

        writer.WritePropertyName("Questions");
        JsonSerializer.Serialize(writer, value.Questions, options);

        writer.WritePropertyName("Answers");
        JsonSerializer.Serialize(writer, value.Answers, options);

        writer.WritePropertyName("Authority");
        JsonSerializer.Serialize(writer, value.Authority, options);

        writer.WritePropertyName("Additional");
        JsonSerializer.Serialize(writer, value.Additional, options);

        writer.WriteEndObject();
    }

    private static void SerializeHeader(Utf8JsonWriter writer, DNSHeader header, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteNumber("Id", header.Id);
        writer.WriteNumber("Flags", header.Flags);

        writer.WriteBoolean("IsResponse", header.IsResponse);
        writer.WriteString("OpCode", header.OpCode.ToString());
        writer.WriteBoolean("IsAuthoritative", header.IsAuthoritative);
        writer.WriteBoolean("RecursionDesired", header.IsRecursionDesired);
        writer.WriteBoolean("RecursionAvailable", header.IsRecursionAvailable);
        writer.WriteString("ResponseCode", header.RCode.ToString());

        writer.WriteNumber("QuestionCount", header.QuestionCount);
        writer.WriteNumber("AnswerCount", header.AnswerCount);
        writer.WriteNumber("AuthorityCount", header.AuthorityCount);
        writer.WriteNumber("AdditionalCount", header.AdditionalCount);
        writer.WriteEndObject();
    }
}