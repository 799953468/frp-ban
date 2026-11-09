using System.Text.Json;
using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

/// <summary>
/// Error message (either direction).
/// </summary>
public sealed record ErrorMessage(
    [property: JsonRequired, JsonPropertyName("Error")] string ErrorText
) : Message(MessageType.Error)
{
    protected override byte[] SerializeBody()
    {
        return JsonSerializer.SerializeToUtf8Bytes(new { Error = ErrorText });
    }

    public static Message FromBody(ReadOnlySpan<byte> body) => DeserializeJson<ErrorMessage>(body);
}
