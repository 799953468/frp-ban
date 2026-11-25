using System.Text.Json;
using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

/// <summary>
/// Ban response message (server -> client). <see cref="Status"/> tells the client whether to
/// drop the request, or keep it queued and retry.
/// </summary>
public sealed record BanResponseMessage(
    [property: JsonRequired] BanStatus Status,
    [property: JsonRequired] string Message
) : Message(MessageType.BanResponse)
{
    /// <summary>True when the address is durably banned.</summary>
    [JsonIgnore]
    public bool Success => Status.IsSuccess();

    protected override byte[] SerializeBody()
    {
        return JsonSerializer.SerializeToUtf8Bytes(this, ProtocolJsonContext.Default.BanResponseMessage);
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        return DeserializeJson(body, ProtocolJsonContext.Default.BanResponseMessage);
    }
}
