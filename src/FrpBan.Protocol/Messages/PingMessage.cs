using System.Buffers.Binary;

namespace FrpBan.Protocol;

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
        if (body.Length is not (0 or 4))
            throw new InvalidDataException("Heartbeat bodies must contain zero or four bytes.");
        var seq = body.Length == 4
            ? BinaryPrimitives.ReadUInt32BigEndian(body)
            : 0u;
        return new PingMessage(seq);
    }
}
