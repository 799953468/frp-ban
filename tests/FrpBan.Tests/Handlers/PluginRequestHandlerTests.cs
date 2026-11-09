using System.Text.Json;
using FrpBan.Handlers;
using FrpBan.Models;
using FrpBan.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace FrpBan.Tests.Handlers;

public class PluginRequestHandlerTests
{
    [Theory]
    [InlineData("Login", "{}")]
    [InlineData("Login", "{\"client_address\":123}")]
    [InlineData("Login", "{\"client_address\":\"not-an-ip\"}")]
    [InlineData("Login", "[]")]
    [InlineData("NewUserConn", "null")]
    [InlineData("NewUserConn", "{\"remote_addr\":\"\"}")]
    public async Task InvalidCallbacks_AreDenied(string operation, string json)
    {
        var handler = new PluginRequestHandler(Mock.Of<IBanService>(), NullLogger<PluginRequestHandler>.Instance);
        var request = new PluginRequest("0.1.0", operation, JsonSerializer.Deserialize<JsonElement>(json));
        Assert.True((await handler.HandleAsync(request, new DefaultHttpContext())).Reject);
    }

    [Theory]
    [InlineData("Login", "client_address", "[::ffff:192.0.2.1]:1234", "192.0.2.1")]
    [InlineData("NewUserConn", "remote_addr", "192.0.2.1:2345", "192.0.2.1")]
    [InlineData("Login", "client_address", "2001:db8::1", "2001:db8::1")]
    public async Task Callbacks_CheckCanonicalIp(string operation, string field, string address, string expected)
    {
        var bans = new Mock<IBanService>();
        bans.Setup(service => service.IsBanned(expected)).Returns(true);
        var handler = new PluginRequestHandler(bans.Object, NullLogger<PluginRequestHandler>.Instance);
        var json = JsonSerializer.SerializeToElement(new Dictionary<string, string> { [field] = address });
        Assert.True((await handler.HandleAsync(new PluginRequest("0.1.0", operation, json), new DefaultHttpContext())).Reject);
        bans.Verify(service => service.IsBanned(expected), Times.Once);
    }
}
