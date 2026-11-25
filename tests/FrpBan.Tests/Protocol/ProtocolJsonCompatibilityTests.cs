using System.Text;
using FrpBan.Protocol;
using Xunit;

namespace FrpBan.Tests.Protocol;

public class ProtocolJsonCompatibilityTests
{
    public static TheoryData<Message, string> WireMessages
    {
        get
        {
            return new TheoryData<Message, string>
            {
                { new HelloMessage("1.0", "client", "hash"), """{"Version":"1.0","ClientType":"client","TokenHash":"hash"}""" },
                { new BanRequestMessage("192.0.2.1", null, null), """{"Ip":"192.0.2.1","Reason":null,"DurationSeconds":null}""" },
                { new BanResponseMessage(BanStatus.Applied, "accepted"), """{"Status":"Applied","Message":"accepted"}""" },
                { new BanResponseMessage(BanStatus.StorageUnavailable, "retry"), """{"Status":"StorageUnavailable","Message":"retry"}""" },
                { new ErrorMessage("invalid token"), """{"Error":"invalid token"}""" },
            };
        }
    }

    [Theory]
    [MemberData(nameof(WireMessages))]
    public void GeneratedJson_MatchesTheWireFormat(Message message, string expectedBody)
    {
        var bytes = message.Serialize();
        Assert.Equal(expectedBody, Encoding.UTF8.GetString(bytes.AsSpan(5)));
        Assert.Equal(message, Message.Deserialize(bytes).message);
    }
}