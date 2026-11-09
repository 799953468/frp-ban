using FrpBan.Protocol;
using Xunit;

namespace FrpBan.Tests.Protocol;

public class MessageTests
{
    [Fact]
    public void HelloMessage_Construction_StoresValues()
    {
        // Arrange
        var version = "1.0";
        var clientType = "test-client";
        var tokenHash = "abc123def456";

        // Act
        var message = new HelloMessage(version, clientType, tokenHash);

        // Assert
        Assert.Equal(version, message.Version);
        Assert.Equal(clientType, message.ClientType);
        Assert.Equal(tokenHash, message.TokenHash);
    }

    [Fact]
    public void HelloMessage_CorrectType()
    {
        // Act
        var message = new HelloMessage("1.0", "client", "hash");

        // Assert
        Assert.Equal(MessageType.Hello, message.Type);
    }

    [Fact]
    public void BanRequestMessage_Construction_StoresValues()
    {
        // Arrange
        var ip = "192.168.1.1";
        var reason = "Brute force attack";
        var duration = 3600;

        // Act
        var message = new BanRequestMessage(ip, reason, duration);

        // Assert
        Assert.Equal(ip, message.Ip);
        Assert.Equal(reason, message.Reason);
        Assert.Equal(duration, message.DurationSeconds);
    }

    [Fact]
    public void BanRequestMessage_CorrectType()
    {
        // Act
        var message = new BanRequestMessage("192.168.1.1", "test", 3600);

        // Assert
        Assert.Equal(MessageType.BanRequest, message.Type);
    }

    [Fact]
    public void BanResponseMessage_SuccessTrue_StoresValues()
    {
        // Arrange
        var message = new BanResponseMessage(true, "Ban applied successfully");

        // Act & Assert
        Assert.True(message.Success);
        Assert.Equal("Ban applied successfully", message.Message);
        Assert.Equal(MessageType.BanResponse, message.Type);
    }

    [Fact]
    public void BanResponseMessage_SuccessFalse_StoresValues()
    {
        // Arrange
        var message = new BanResponseMessage(false, "Ban failed");

        // Act & Assert
        Assert.False(message.Success);
        Assert.Equal("Ban failed", message.Message);
    }

    [Fact]
    public void PingMessage_CorrectType()
    {
        // Act
        var message = new PingMessage(1);

        // Assert
        Assert.Equal(MessageType.Ping, message.Type);
        Assert.Equal(1u, message.SequenceNumber);
    }

    [Fact]
    public void PongMessage_CorrectType()
    {
        // Act
        var message = new PongMessage(1);

        // Assert
        Assert.Equal(MessageType.Pong, message.Type);
        Assert.Equal(1u, message.SequenceNumber);
    }

    [Fact]
    public void ErrorMessage_StoresError()
    {
        // Arrange
        var errorText = "Connection timeout";

        // Act
        var message = new ErrorMessage(errorText);

        // Assert
        Assert.Equal(errorText, message.ErrorText);
        Assert.Equal(MessageType.Error, message.Type);
    }

    [Fact]
    public void Message_Serialize_ProducesBytes()
    {
        // Arrange
        var message = new PingMessage(42);

        // Act
        var bytes = message.Serialize();

        // Assert
        Assert.NotEmpty(bytes);
        Assert.True(bytes.Length >= 5); // type(1) + length(4) + body
    }

    [Fact]
    public void Message_SerializeDeserialize_RoundTrip()
    {
        // Arrange
        var original = new BanRequestMessage("10.0.0.1", "Test reason", 7200);

        // Act
        var serialized = original.Serialize();
        var (deserialized, bytesRead) = Message.Deserialize(serialized);

        // Assert
        Assert.NotNull(deserialized);
        Assert.IsType<BanRequestMessage>(deserialized);
        var banMsg = (BanRequestMessage)deserialized;
        Assert.Equal("10.0.0.1", banMsg.Ip);
        Assert.Equal("Test reason", banMsg.Reason);
        Assert.Equal(7200, banMsg.DurationSeconds);
        Assert.Equal(serialized.Length, bytesRead);
    }

    [Fact]
    public void Message_Deserialize_IncompleteData_ReturnsNull()
    {
        // Arrange - Only 3 bytes when we need 5
        var buffer = new byte[] { 1, 2, 3 };

        // Act
        var (message, bytesRead) = Message.Deserialize(buffer);

        // Assert
        Assert.Null(message);
        Assert.Equal(0, bytesRead);
    }

    [Fact]
    public void Message_MaxBodySize_Enforced()
    {
        // Assert - Verify constant is set
        Assert.Equal(65536, Message.MaxBodySize);
    }
}
