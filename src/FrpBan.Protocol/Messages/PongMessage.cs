using System.Buffers.Binary;

namespace FrpBan.Protocol;

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
        if (body.Length is not (0 or 4))
            throw new InvalidDataException("Heartbeat bodies must contain zero or four bytes.");
        var seq = body.Length == 4
            ? BinaryPrimitives.ReadUInt32BigEndian(body)
            : 0u;
        return new PongMessage(seq);
    }
}
