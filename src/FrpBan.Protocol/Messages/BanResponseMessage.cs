using System.Text.Json;
using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

/// <summary>
/// Ban response message (server -> client).
/// </summary>
public sealed record BanResponseMessage(
    [property: JsonRequired] bool Success,
    [property: JsonRequired] string Message
) : Message(MessageType.BanResponse)
{
    protected override byte[] SerializeBody()
    {
        return JsonSerializer.SerializeToUtf8Bytes(new { Success, Message });
    }

    public static Message FromBody(ReadOnlySpan<byte> body) => DeserializeJson<BanResponseMessage>(body);
}
