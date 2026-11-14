using System.Text.Json;
using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

/// <summary>
/// Handshake message (client -> server).
/// </summary>
public sealed record HelloMessage(
    [property: JsonRequired] string Version,
    [property: JsonRequired] string ClientType,
    [property: JsonRequired] string TokenHash // SHA256 hash of token
) : Message(MessageType.Hello)
{
    protected override byte[] SerializeBody()
    {
        return JsonSerializer.SerializeToUtf8Bytes(this, ProtocolJsonContext.Default.HelloMessage);
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        return DeserializeJson(body, ProtocolJsonContext.Default.HelloMessage);
    }
}