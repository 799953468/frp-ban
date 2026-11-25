using System.Text.Json;
using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

/// <summary>
/// Handshake message (client -> server, and the server's reply).
/// TokenHash is the hex SHA-256 of the shared token. It is itself a bearer credential and
/// relies on TLS for confidentiality; the server replies with an empty TokenHash.
/// </summary>
public sealed record HelloMessage(
    [property: JsonRequired] string Version,
    [property: JsonRequired] string ClientType,
    [property: JsonRequired] string TokenHash
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