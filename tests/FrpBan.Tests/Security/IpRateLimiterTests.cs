using FrpBan.Security;
using Xunit;

namespace FrpBan.Tests.Security;

public class IpRateLimiterTests
{
    [Fact]
    public void ConcurrentRequests_EnforceOneSharedBudget()
    {
        var limiter = new IpRateLimiter(10);
        var accepted = 0;
        Parallel.For(0, 1000, _ => { if (limiter.TryAcquire("192.0.2.1")) Interlocked.Increment(ref accepted); });
        Assert.Equal(10, accepted);
        Assert.True(limiter.TryAcquire("192.0.2.2"));
    }

    [Fact]
    public void AddressState_HasAHardLimit()
    {
        var limiter = new IpRateLimiter(10, maxAddresses: 1);
        Assert.True(limiter.TryAcquire("192.0.2.1"));
        Assert.False(limiter.TryAcquire("192.0.2.2"));
    }
}
