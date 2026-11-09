using System.Buffers.Binary;
using FrpBan.Protocol;
using FrpBan.Protocol.Transport;
using Xunit;

namespace FrpBan.Tests.Protocol;

public class MessageTransportTests
{
    [Fact]
    public void NullableBanFields_RoundTrip()
    {
        var original = new BanRequestMessage("192.0.2.1", null, null);
        Assert.Equal(original, Message.Deserialize(original.Serialize()).message);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(10)]
    [InlineData(int.MaxValue)]
    public void InvalidOffset_IsRejected(int offset) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Message.Deserialize(new byte[5], offset));

    [Fact]
    public void PartialSpan_DoesNotReadTrailingBufferBytes()
    {
        var frame = new PingMessage(123).Serialize();
        Assert.Null(Message.Deserialize(frame.AsSpan(0, 6)).message);
    }

    [Fact]
    public async Task FragmentedAndCoalescedFrames_AreReadExactlyOnce()
    {
        Message[] messages = [new HelloMessage("1.0", "client", "hash"),
            new BanRequestMessage("192.0.2.1", null, null), new PingMessage(42)];
        await using var stream = new FragmentedStream(messages.SelectMany(message => message.Serialize()).ToArray());
        foreach (var expected in messages)
            Assert.Equal(expected, await MessageTransport.ReadAsync(stream));
        Assert.Null(await MessageTransport.ReadAsync(stream));
    }

    [Fact]
    public async Task OversizedHeader_IsRejectedBeforeReadingTheBody()
    {
        var header = new byte[5];
        header[0] = (byte)MessageType.Hello;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(1), Message.MaxBodySize + 1);
        await using var stream = new MemoryStream(header);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await MessageTransport.ReadAsync(stream));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(6)]
    public async Task TruncatedFrames_ThrowInsteadOfParsingStaleBytes(int length)
    {
        await using var stream = new FragmentedStream(new PingMessage(1).Serialize()[..length]);
        await Assert.ThrowsAsync<EndOfStreamException>(async () => await MessageTransport.ReadAsync(stream));
    }

    [Fact]
    public async Task UnknownType_IsRejected()
    {
        await using var stream = new MemoryStream(new byte[] { 255, 0, 0, 0, 0 });
        await Assert.ThrowsAsync<InvalidDataException>(async () => await MessageTransport.ReadAsync(stream));
    }

    [Fact]
    public void InvalidHeartbeatLength_IsRejected() => Assert.Throws<InvalidDataException>(() =>
        Message.Deserialize(new byte[] { (byte)MessageType.Ping, 0, 0, 0, 1, 42 }));

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"Ip\":null}")]
    [InlineData("{\"Ip\":123}")]
    public void InvalidRequiredJsonFields_AreRejected(string body)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(body);
        var frame = new byte[bytes.Length + 5];
        frame[0] = (byte)MessageType.BanRequest;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), (uint)bytes.Length);
        bytes.CopyTo(frame, 5);
        Assert.Throws<System.Text.Json.JsonException>(() => Message.Deserialize(frame));
    }

    private sealed class FragmentedStream(byte[] data) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, 1)], cancellationToken);
    }
}
