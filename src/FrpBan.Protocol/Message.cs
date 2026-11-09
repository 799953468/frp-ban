using System.Buffers.Binary;
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
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, buffer.Length);
        return Deserialize(buffer.AsSpan(offset));
    }

    /// <summary>Parses only the bytes actually received, without copying the frame.</summary>
    public static (Message? message, int bytesRead) Deserialize(ReadOnlySpan<byte> buffer)
    {
        // Need at least 5 bytes: type(1) + length(4)
        if (buffer.Length < 5)
            return (null, 0);

        var type = (MessageType)buffer[0];
        var bodyLength = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(1, 4));

        // Security: enforce maximum message size (64KB)
        if (bodyLength > MaxBodySize)
            throw new InvalidOperationException($"Message body too large: {bodyLength} bytes (max: {MaxBodySize})");

        var totalLength = 5 + (int)bodyLength;
        if (totalLength > buffer.Length)
            return (null, 0); // Incomplete message

        var bodyBytes = buffer.Slice(5, (int)bodyLength);
        var message = DeserializeBody(type, bodyBytes);

        return (message, totalLength);
    }

    /// <summary>
    /// Subclasses implement to serialize their specific body content.
    /// </summary>
    protected abstract byte[] SerializeBody();

    private static readonly JsonSerializerOptions JsonOptions = new() { RespectNullableAnnotations = true };

    /// <summary>Deserializes a message directly from UTF-8 with non-nullable field validation.</summary>
    protected static T DeserializeJson<T>(ReadOnlySpan<byte> body) where T : Message =>
        JsonSerializer.Deserialize<T>(body, JsonOptions) ?? throw new JsonException("Message body cannot be null.");


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
