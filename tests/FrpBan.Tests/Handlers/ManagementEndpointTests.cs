using System.Net;
using System.Net.Http.Headers;
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
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FrpBan.Tests.Handlers;

public sealed class ManagementEndpointTests
{
    private const string ClientToken = "test-client-token-with-at-least-32-characters";
    private const string ManagementToken = "test-management-token-with-at-least-32-characters";

    [Theory]
    [InlineData("/admin/")]
    [InlineData("/admin/app.js")]
    [InlineData("/admin/app.css")]
    [InlineData("/admin/api/bans")]
    public async Task DisabledManagement_DoesNotExposeRoutes(string path)
    {
        await using (var server = await TestServer.StartAsync(settings => { settings.WebUi.Enabled = false; }))
        using (var response = await server.Client.GetAsync(path))
        {
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    [Theory]
    [InlineData("/admin/api/bans")]
    [InlineData("/admin/api/bans/")]
    [InlineData("/ADMIN/API/BANS")]
    public async Task MissingToken_IsRejectedBeforeBodyParsing(string path)
    {
        await using (var server = await TestServer.StartAsync(authenticate: false))
        using (var response = await server.Client.PostAsync(path, new StringContent("{broken", Encoding.UTF8, "application/json")))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Bearer");
            Assert.Empty(server.Bans.GetActiveBans());
        }
    }

    [Theory]
    [InlineData("GET", "/admin/api/bans")]
    [InlineData("POST", "/admin/api/bans")]
    [InlineData("DELETE", "/admin/api/bans/192.0.2.10")]
    public async Task ClientToken_CannotManageBans(string method, string path)
    {
        await using (var server = await TestServer.StartAsync())
        {
            server.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ClientToken);
            using (var request = new HttpRequestMessage(new HttpMethod(method), path))
            using (var response = await server.Client.SendAsync(request))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            }
        }
    }

    [Theory]
    [InlineData("/admin/")]
    [InlineData("/admin/app.js")]
    [InlineData("/admin/api/bans")]
    public async Task DisallowedSocketAddress_CannotSpoofForwardingHeaders(string path)
    {
        await using (var server = await TestServer.StartAsync(settings => { settings.WebUi.AllowedAddresses = ["192.0.2.0/24"]; }))
        {
            server.Client.DefaultRequestHeaders.Add("X-Forwarded-For", "192.0.2.1");
            using (var response = await server.Client.GetAsync(path))
            {
                Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            }
        }
    }

    [Theory]
    [InlineData("/admin/", "text/html", "Ban management")]
    [InlineData("/admin/app.js", "text/javascript", "textContent")]
    [InlineData("/admin/app.css", "text/css", ":focus-visible")]
    public async Task EmbeddedAssets_AreAvailableWithoutWorkingDirectoryFiles(string path, string mediaType, string expected)
    {
        await using (var server = await TestServer.StartAsync(authenticate: false))
        using (var response = await server.Client.GetAsync(path))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(mediaType, response.Content.Headers.ContentType!.MediaType);
            Assert.Contains(expected, await response.Content.ReadAsStringAsync());
            Assert.True(response.Headers.CacheControl!.NoStore);
            Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        }
    }

    [Fact]
    public async Task AdminWithoutSlash_RedirectsForRelativeAssets()
    {
        await using (var server = await TestServer.StartAsync(authenticate: false))
        using (var response = await server.Client.GetAsync("/admin"))
        {
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Equal("/admin/", response.Headers.Location!.OriginalString);
        }
    }

    [Fact]
    public async Task TokenInQueryString_DoesNotAuthenticate()
    {
        await using (var server = await TestServer.StartAsync(authenticate: false))
        using (var response = await server.Client.GetAsync("/admin/api/bans?token=" + ManagementToken))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Fact]
    public async Task BanAndUnban_ChangeTheFrpsCallbackAndCanonicalList()
    {
        await using (var server = await TestServer.StartAsync())
        {
            using (var created = await server.Client.PostAsJsonAsync("/admin/api/bans", new
                       { ip = "::ffff:192.0.2.10", reason = "Manual SSH abuse", durationSeconds = 0 }))
            {
                Assert.Equal(HttpStatusCode.NoContent, created.StatusCode);
            }

            var listing = await server.Client.GetFromJsonAsync<BanListResponse>("/admin/api/bans");
            Assert.Equal("192.0.2.10", Assert.Single(listing!.Items).Ip);
            Assert.Equal(1, listing.PermanentCount);
            Assert.True(await server.IsCallbackRejectedAsync("192.0.2.10:12345"));

            using (var removed = await server.Client.DeleteAsync("/admin/api/bans/192.0.2.10"))
            {
                Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
            }

            Assert.False(await server.IsCallbackRejectedAsync("192.0.2.10:12345"));
            Assert.Empty(server.Bans.GetActiveBans());
        }
    }

    [Fact]
    public async Task Ipv6Ban_UsesDefaultDurationAndCanBeRemoved()
    {
        await using (var server = await TestServer.StartAsync(settings => { settings.DefaultBanDurationSeconds = 900; }))
        {
            using (var response = await server.Client.PostAsJsonAsync("/admin/api/bans", new { ip = "2001:db8::10", reason = "IPv6 test" }))
            {
                Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            }

            var entry = Assert.Single(server.Bans.GetActiveBans());
            Assert.Equal(TimeSpan.FromSeconds(900), entry.ExpiresAt - entry.BannedAt);
            using (var response = await server.Client.DeleteAsync("/admin/api/bans/" + Uri.EscapeDataString(entry.Ip)))
            {
                Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            }

            Assert.Empty(server.Bans.GetActiveBans());
        }
    }

    [Fact]
    public async Task ExemptAddress_IsRejectedAndStrongerBanIsPreserved()
    {
        await using (var server = await TestServer.StartAsync(settings => { settings.ExemptAddresses = ["192.0.2.0/24"]; }))
        {
            using (var response = await server.Client.PostAsJsonAsync("/admin/api/bans", new { ip = "192.0.2.1", reason = "Exempt" }))
            {
                Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            }

            await server.Bans.BanAsync("198.51.100.1", "Original reason", 0);
            using (var response = await server.Client.PostAsJsonAsync("/admin/api/bans", new { ip = "198.51.100.1", reason = "Shorter", durationSeconds = 60 }))
            {
                Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            }

            var entry = Assert.Single(server.Bans.GetActiveBans());
            Assert.Null(entry.ExpiresAt);
            Assert.Equal("Original reason", entry.Reason);
        }
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{broken")]
    [InlineData("{}")]
    [InlineData("{\"ip\":\"example.com\",\"reason\":\"test\"}")]
    [InlineData("{\"ip\":\"192.0.2.1:22\",\"reason\":\"test\"}")]
    [InlineData("{\"ip\":\"192.0.2.1\",\"reason\":\" \"}")]
    [InlineData("{\"ip\":\"192.0.2.1\",\"reason\":\"test\",\"durationSeconds\":-1}")]
    [InlineData("{\"ip\":\"192.0.2.1\",\"reason\":\"test\",\"durationSeconds\":1.5}")]
    [InlineData("{\"ip\":\"192.0.2.1\",\"reason\":\"test\",\"durationSeconds\":2147483648}")]
    public async Task InvalidRequest_ReturnsUsefulErrorWithoutChangingBans(string body)
    {
        await using (var server = await TestServer.StartAsync())
        using (var response = await server.Client.PostAsync("/admin/api/bans", new StringContent(body, Encoding.UTF8, "application/json")))
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.False(string.IsNullOrWhiteSpace((await response.Content.ReadFromJsonAsync<ManagementError>())!.Error));
            Assert.Empty(server.Bans.GetActiveBans());
        }
    }

    [Fact]
    public async Task NonJsonAndOversizedRequests_AreRejected()
    {
        await using (var server = await TestServer.StartAsync())
        {
            using (var response = await server.Client.PostAsync("/admin/api/bans", new StringContent("ip=192.0.2.1")))
            {
                Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
            }

            using (var response = await server.Client.PostAsJsonAsync("/admin/api/bans", new { ip = "192.0.2.1", reason = new string('x', 1025) }))
            {
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            }

            using (var response = await server.Client.PostAsJsonAsync("/admin/api/bans", new { ip = "192.0.2.1", reason = new string('x', 70000) }))
            {
                Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
            }

            Assert.Empty(server.Bans.GetActiveBans());
        }
    }

    [Theory]
    [InlineData("page=0")]
    [InlineData("page=-1")]
    [InlineData("page=not-a-number")]
    [InlineData("pageSize=101")]
    [InlineData("pageSize=0")]
    [InlineData("kind=expired")]
    public async Task InvalidPagination_IsRejected(string query)
    {
        await using (var server = await TestServer.StartAsync())
        using (var response = await server.Client.GetAsync("/admin/api/bans?" + query))
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task SearchFilterAndPaging_ReturnBoundedResultsAndGlobalCounts()
    {
        await using (var server = await TestServer.StartAsync())
        {
            for (var index = 1; index <= 30; index++)
            {
                await server.Bans.BanAsync($"192.0.2.{index}", "SSH abuse", 0);
            }

            await server.Bans.BanAsync("2001:db8::1", "Web abuse", 3600);
            var page = await server.Client.GetFromJsonAsync<BanListResponse>("/admin/api/bans?search=ssh&kind=permanent&pageSize=10&page=2");
            Assert.Equal(10, page!.Items.Length);
            Assert.Equal(30, page.Total);
            Assert.Equal(31, page.ActiveCount);
            Assert.Equal(30, page.PermanentCount);
            Assert.Equal(2, page.Page);

            var last = await server.Client.GetFromJsonAsync<BanListResponse>("/admin/api/bans?kind=temporary&page=2147483647");
            Assert.Equal("2001:db8::1", Assert.Single(last!.Items).Ip);
            Assert.Equal(1, last.Page);
            var empty = await server.Client.GetFromJsonAsync<BanListResponse>("/admin/api/bans?search=no-match");
            Assert.Empty(empty!.Items);
            Assert.Equal(0, empty.Total);
        }
    }

    [Fact]
    public async Task CapacityAndInvalidRemoval_ReturnExpectedStatuses()
    {
        await using (var server = await TestServer.StartAsync(settings => { settings.MaxBanEntries = 1; }))
        {
            await server.Bans.BanAsync("192.0.2.1", "Existing", 0);
            using (var response = await server.Client.PostAsJsonAsync("/admin/api/bans", new { ip = "192.0.2.2", reason = "Full" }))
            {
                Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            }

            using (var response = await server.Client.DeleteAsync("/admin/api/bans/not-an-ip"))
            {
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            }

            using (var response = await server.Client.DeleteAsync("/admin/api/bans/192.0.2.99"))
            {
                Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            }
        }
    }

    [Fact]
    public async Task AuthenticationAttempts_AreRateLimited()
    {
        await using (var server = await TestServer.StartAsync(authenticate: false))
        {
            for (var index = 0; index < 120; index++)
            {
                using (var response = await server.Client.GetAsync("/admin/api/bans"))
                {
                    Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                }
            }

            using (var response = await server.Client.GetAsync("/admin/api/bans"))
            {
                Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
                Assert.Equal(TimeSpan.FromSeconds(60), response.Headers.RetryAfter!.Delta);
            }
        }
    }

    [Fact]
    public async Task ManagementChanges_PersistAcrossStoreRestart()
    {
        await using (var server = await TestServer.StartAsync())
        {
            using (var response = await server.Client.PostAsJsonAsync("/admin/api/bans", new { ip = "192.0.2.1", reason = "Persisted", durationSeconds = 0 }))
            {
                Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            }

            await server.Bans.DisposeAsync();
            await using (var reloaded = new BanService(Options.Create(server.Settings), NullLogger<BanService>.Instance))
            {
                reloaded.Load();
                Assert.Equal("Persisted", Assert.Single(reloaded.GetActiveBans()).Reason);
            }
        }
    }

    private sealed class TestServer : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly string _directory;
        public HttpClient Client { get; }
        public BanService Bans { get; }
        public PluginSettings Settings { get; }

        private TestServer(WebApplication app, BanService bans, PluginSettings settings, string directory)
        {
            _app = app;
            Bans = bans;
            Settings = settings;
            _directory = directory;
            var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            Client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                BaseAddress = new Uri(address), Timeout = TimeSpan.FromSeconds(10)
            };
        }

        public static async Task<TestServer> StartAsync(Action<PluginSettings>? configure = null, bool authenticate = true)
        {
            var directory = Path.Combine(Path.GetTempPath(), "frp-ban-management-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var settings = new PluginSettings
            {
                Token = ClientToken,
                BanFilePath = Path.Combine(directory, "bans.json"),
                WebUi = new WebUiSettings { Enabled = true, Token = ManagementToken }
            };
            configure?.Invoke(settings);
            var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Testing", ContentRootPath = directory });
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Listen(IPAddress.Loopback, 0);
                options.Limits.MaxRequestBodySize = 65536;
            });
            var bans = new BanService(Options.Create(settings), NullLogger<BanService>.Instance);
            builder.Services.AddSingleton(Options.Create(settings));
            builder.Services.AddSingleton<IBanService>(bans);
            builder.Services.AddSingleton<PluginAddressFilter>();
            builder.Services.AddSingleton<PluginRequestHandler>();
            var app = builder.Build();
            try
            {
                app.MapPluginEndpoints();
                app.MapManagementEndpoints();
                await app.StartAsync();
                var server = new TestServer(app, bans, settings, directory);
                if (authenticate)
                {
                    server.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ManagementToken);
                }

                return server;
            }
            catch
            {
                await app.DisposeAsync();
                await bans.DisposeAsync();
                Directory.Delete(directory, true);
                throw;
            }
        }

        public async Task<bool> IsCallbackRejectedAsync(string address)
        {
            using (var response = await Client.PostAsJsonAsync("/handler", new PluginRequest("0.1.0", "Login",
                       JsonSerializer.SerializeToElement(new { client_address = address }))))
            {
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                return (await response.Content.ReadFromJsonAsync<PluginResponse>())!.Reject;
            }
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _app.DisposeAsync();
            await Bans.DisposeAsync();
            Directory.Delete(_directory, true);
        }
    }
}