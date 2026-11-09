using System.Text.Json;
using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

/// <summary>
/// Ban request message (client -> server).
/// </summary>
public sealed record BanRequestMessage(
    [property: JsonRequired] string Ip,
    string? Reason,
    int? DurationSeconds
) : Message(MessageType.BanRequest)
{
    protected override byte[] SerializeBody()
    {
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            Ip,
            Reason,
            DurationSeconds,
        });
    }

    public static Message FromBody(ReadOnlySpan<byte> body) => DeserializeJson<BanRequestMessage>(body);
}
