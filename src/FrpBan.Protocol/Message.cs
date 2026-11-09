using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace FrpBan.Protocol;

/// <summary>
/// Binary message format: [Type(1B)] [Length(4B)] [Body(variable)]
/// Maximum message size: 64KB (security limit)
/// </summary>
public abstract record Message(MessageType Type)
{
    /// <summary>
    /// Maximum message body size (64KB - prevents DoS attacks)
    /// </summary>
    public const int MaxBodySize = 65536;

    /// <summary>
    /// Serializes message to byte array.
    /// Format: [type:1B][length:4B][body:variable]
    /// </summary>
    public byte[] Serialize()
    {
        var bodyBytes = SerializeBody();
        if (bodyBytes.Length > MaxBodySize)
            throw new InvalidOperationException($"Message body exceeds maximum size: {bodyBytes.Length} > {MaxBodySize}");

        var totalLength = 1 + 4 + bodyBytes.Length; // type + length + body
        var buffer = new byte[totalLength];

        buffer[0] = (byte)Type;
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(1, 4), (uint)bodyBytes.Length);
        Buffer.BlockCopy(bodyBytes, 0, buffer, 5, bodyBytes.Length);

        return buffer;
    }

    /// <summary>
    /// Deserializes message from byte array.
    /// Returns null if incomplete message (need more data).
    /// </summary>
    public static (Message? message, int bytesRead) Deserialize(byte[] buffer, int offset = 0)
    {
        // Need at least 5 bytes: type(1) + length(4)
        if (offset + 5 > buffer.Length)
            return (null, 0);

        var type = (MessageType)buffer[offset];
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(offset + 1, 4));

        // Security: enforce maximum message size (64KB)
        if (bodyLength > MaxBodySize)
            throw new InvalidOperationException($"Message body too large: {bodyLength} bytes (max: {MaxBodySize})");

        var totalLength = 5 + (int)bodyLength;
        if (offset + totalLength > buffer.Length)
            return (null, 0); // Incomplete message

        var bodyBytes = buffer.AsSpan(offset + 5, (int)bodyLength);
        var message = DeserializeBody(type, bodyBytes);

        return (message, totalLength);
    }

    /// <summary>
    /// Subclasses implement to serialize their specific body content.
    /// </summary>
    protected abstract byte[] SerializeBody();

    /// <summary>
    /// Factory method to deserialize body based on message type.
    /// </summary>
    private static Message? DeserializeBody(MessageType type, ReadOnlySpan<byte> body)
    {
        return type switch
        {
            MessageType.Hello => HelloMessage.FromBody(body),
            MessageType.BanRequest => BanRequestMessage.FromBody(body),
            MessageType.BanResponse => BanResponseMessage.FromBody(body),
            MessageType.Ping => PingMessage.FromBody(body),
            MessageType.Pong => PongMessage.FromBody(body),
            MessageType.Error => ErrorMessage.FromBody(body),
            _ => throw new InvalidOperationException($"Unknown message type: {type}"),
        };
    }
}

/// <summary>
/// Handshake message (client -> server).
/// </summary>
public sealed record HelloMessage(
    string Version,
    string ClientType,
    string TokenHash  // SHA256 hash of token
) : Message(MessageType.Hello)
{
    protected override byte[] SerializeBody()
    {
        var json = JsonSerializer.Serialize(new
        {
            Version,
            ClientType,
            TokenHash,
        });
        return Encoding.UTF8.GetBytes(json);
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        var json = Encoding.UTF8.GetString(body);
        using var doc = JsonDocument.Parse(json);  // FIX: Dispose JsonDocument
        var root = doc.RootElement;

        return new HelloMessage(
            root.GetProperty("Version").GetString() ?? "1.0",
            root.GetProperty("ClientType").GetString() ?? "unknown",
            root.GetProperty("TokenHash").GetString() ?? ""
        );
    }
}

/// <summary>
/// Ban request message (client -> server).
/// </summary>
public sealed record BanRequestMessage(
    string Ip,
    string? Reason,
    int? DurationSeconds
) : Message(MessageType.BanRequest)
{
    protected override byte[] SerializeBody()
    {
        var json = JsonSerializer.Serialize(new
        {
            Ip,
            Reason,
            DurationSeconds,
        });
        return Encoding.UTF8.GetBytes(json);
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        var json = Encoding.UTF8.GetString(body);
        using var doc = JsonDocument.Parse(json);  // FIX: Dispose JsonDocument
        var root = doc.RootElement;

        return new BanRequestMessage(
            root.GetProperty("Ip").GetString() ?? "",
            root.TryGetProperty("Reason", out var reason) ? reason.GetString() : null,
            root.TryGetProperty("DurationSeconds", out var duration) ? duration.GetInt32() : null
        );
    }
}

/// <summary>
/// Ban response message (server -> client).
/// </summary>
public sealed record BanResponseMessage(
    bool Success,
    string Message
) : Message(MessageType.BanResponse)
{
    protected override byte[] SerializeBody()
    {
        var json = JsonSerializer.Serialize(new { Success, Message });
        return Encoding.UTF8.GetBytes(json);
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        var json = Encoding.UTF8.GetString(body);
        using var doc = JsonDocument.Parse(json);  // FIX: Dispose JsonDocument
        var root = doc.RootElement;

        return new BanResponseMessage(
            root.GetProperty("Success").GetBoolean(),
            root.GetProperty("Message").GetString() ?? ""
        );
    }
}

/// <summary>
/// Ping message (client -> server).
/// </summary>
public sealed record PingMessage(
    uint SequenceNumber = 0
) : Message(MessageType.Ping)
{
    protected override byte[] SerializeBody()
    {
        var buffer = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, SequenceNumber);
        return buffer;
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        var seq = body.Length >= 4
            ? BinaryPrimitives.ReadUInt32BigEndian(body)
            : 0u;
        return new PingMessage(seq);
    }
}

/// <summary>
/// Pong response message (server -> client).
/// </summary>
public sealed record PongMessage(
    uint SequenceNumber = 0
) : Message(MessageType.Pong)
{
    protected override byte[] SerializeBody()
    {
        var buffer = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, SequenceNumber);
        return buffer;
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        var seq = body.Length >= 4
            ? BinaryPrimitives.ReadUInt32BigEndian(body)
            : 0u;
        return new PongMessage(seq);
    }
}

/// <summary>
/// Error message (either direction).
/// </summary>
public sealed record ErrorMessage(
    string ErrorText
) : Message(MessageType.Error)
{
    protected override byte[] SerializeBody()
    {
        var json = JsonSerializer.Serialize(new { Error = ErrorText });
        return Encoding.UTF8.GetBytes(json);
    }

    public static Message FromBody(ReadOnlySpan<byte> body)
    {
        var json = Encoding.UTF8.GetString(body);
        using var doc = JsonDocument.Parse(json);  // FIX: Dispose JsonDocument
        return new ErrorMessage(
            doc.RootElement.GetProperty("Error").GetString() ?? "Unknown error"
        );
    }
}
