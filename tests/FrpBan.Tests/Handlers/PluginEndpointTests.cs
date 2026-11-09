using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FrpBan.Configuration;
using FrpBan.Endpoints;
using FrpBan.Handlers;
using FrpBan.Models;
using FrpBan.Security;
using FrpBan.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace FrpBan.Tests.Handlers;

public class PluginEndpointTests
{
    [Theory]
    [InlineData("/handler")]
    [InlineData("/handler/")]
    [InlineData("/HANDLER")]
    public async Task UnauthorizedPeer_IsRejectedBeforeParsingJson(string path)
    {
        await using var app = CreateApplication(["192.0.2.0/24"]);
        await app.StartAsync();
        using var client = CreateClient(app);
        using var response = await client.PostAsync(path, new StringContent("{broken", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Callback_BlocksTheBannedCanonicalIp()
    {
        var bans = new Mock<IBanService>();
        bans.Setup(service => service.IsBanned("192.0.2.1")).Returns(true);
        await using var app = CreateApplication(["127.0.0.1"], bans.Object);
        await app.StartAsync();
        using var client = CreateClient(app);
        using var response = await client.PostAsJsonAsync("/handler", new PluginRequest("0.1.0", "Login",
            JsonSerializer.SerializeToElement(new { client_address = "[::ffff:192.0.2.1]:1234" })));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True((await response.Content.ReadFromJsonAsync<PluginResponse>())!.Reject);
    }

    [Fact]
    public async Task OversizedHttpBody_IsRejected()
    {
        await using var app = CreateApplication(["127.0.0.1"]);
        await app.StartAsync();
        using var client = CreateClient(app);
        var body = "{\"op\":\"Ping\",\"content\":{\"padding\":\"" + new string('x', 70000) + "\"}}";
        using var response = await client.PostAsync("/handler", new StringContent(body, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    private static WebApplication CreateApplication(List<string> allowed, IBanService? bans = null)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, 0);
            options.Limits.MaxRequestBodySize = 65536;
        });
        builder.Services.AddSingleton(Options.Create(new PluginSettings { AllowedPluginAddresses = allowed }));
        builder.Services.AddSingleton(bans ?? Mock.Of<IBanService>());
        builder.Services.AddSingleton<PluginRequestHandler>();
        builder.Services.AddSingleton<PluginAddressFilter>();
        var app = builder.Build();
        app.MapPluginEndpoints();
        return app;
    }

    private static HttpClient CreateClient(WebApplication app)
    {
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new HttpClient { BaseAddress = new Uri(address), Timeout = TimeSpan.FromSeconds(5) };
    }
}
