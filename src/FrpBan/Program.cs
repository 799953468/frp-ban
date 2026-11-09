using System.Net;
using System.Net.Sockets;
using FrpBan.Configuration;
using FrpBan.Handlers;
using FrpBan.Middleware;
using FrpBan.Models;
using FrpBan.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;

// -------------------------------------------------------------------------
// Configuration Loading
// -------------------------------------------------------------------------
var config = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

// Load PluginSettings to get log path
var pluginSettings = config.GetSection("PluginSettings").Get<PluginSettings>() ?? new PluginSettings();

// -------------------------------------------------------------------------
// Serilog Configuration
// -------------------------------------------------------------------------
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(config)
    .WriteTo.Async(a => a.File(
        path: pluginSettings.AppLogPath,
        rollingInterval: RollingInterval.Day,
        rollOnFileSizeLimit: true,
        fileSizeLimitBytes: 104857600,
        retainedFileCountLimit: 30,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
        restrictedToMinimumLevel: LogEventLevel.Information
    ), bufferSize: 10000, blockWhenFull: false)
    .CreateLogger();

try
{
    Log.Information("Starting frp-ban server");

var builder = WebApplication.CreateBuilder(args);

// Use Serilog for all logging
builder.Host.UseSerilog();

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------
builder.Services.AddOptions<PluginSettings>()
    .Bind(builder.Configuration.GetSection("PluginSettings"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// -------------------------------------------------------------------------
// Services
// -------------------------------------------------------------------------
builder.Services.AddSingleton<BanService>();
builder.Services.AddSingleton<IBanService>(sp => sp.GetRequiredService<BanService>());
builder.Services.AddSingleton<AccessLogService>();
builder.Services.AddSingleton<IAccessLogService>(sp => sp.GetRequiredService<AccessLogService>());
builder.Services.AddSingleton<PluginRequestHandler>();

var app = builder.Build();

// Load persisted bans before accepting traffic.
app.Services.GetRequiredService<BanService>().Load();

// Ensure proper disposal on shutdown
app.Lifetime.ApplicationStopping.Register(() =>
{
    var banService = app.Services.GetRequiredService<BanService>();
    banService.Dispose();

    var accessLogService = app.Services.GetRequiredService<AccessLogService>();
    accessLogService.Dispose();
});

// -------------------------------------------------------------------------
// Middleware
// -------------------------------------------------------------------------
app.UseSerilogRequestLogging(options =>
{
    options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
    options.GetLevel = (httpContext, elapsed, ex) => ex != null
        ? Serilog.Events.LogEventLevel.Error
        : httpContext.Response.StatusCode > 499
            ? Serilog.Events.LogEventLevel.Error
            : Serilog.Events.LogEventLevel.Information;
    options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
    {
        diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value);
        diagnosticContext.Set("RequestScheme", httpContext.Request.Scheme);
        diagnosticContext.Set("RemoteIP", httpContext.Connection.RemoteIpAddress);
    };
});

app.UseMiddleware<TokenAuthMiddleware>();

// -------------------------------------------------------------------------
// Routes — frps plugin endpoint
// -------------------------------------------------------------------------

/// <summary>
/// POST /handler  — called by frps for every plugin operation.
/// Restricted to addresses listed in AllowedPluginAddresses (supports CIDR).
/// </summary>
app.MapPost("/handler", async (
    [FromBody] PluginRequest request,
    HttpContext ctx,
    PluginRequestHandler handler,
    IOptions<PluginSettings> opts) =>
{
    var allowed = opts.Value.AllowedPluginAddresses;
    if (allowed.Count > 0)
    {
        var remote = ctx.Connection.RemoteIpAddress;
        if (remote is null || !IsIpAllowed(remote, allowed))
        {
            return Results.Json(PluginResponse.Deny("not allowed"), statusCode: 403);
        }
    }

    var response = await handler.HandleAsync(request, ctx);
    return Results.Json(response);
});

// -------------------------------------------------------------------------
// Routes — ban management API (protected by TokenAuthMiddleware)
// -------------------------------------------------------------------------

var api = app.MapGroup("/api");

/// <summary>GET /api/bans — list all active bans.</summary>
api.MapGet("/bans", (IBanService bans) =>
    Results.Ok(bans.GetActiveBans()));

/// <summary>
/// POST /api/bans — add an IP to the ban list.
/// Body: { "ip": "1.2.3.4", "reason": "...", "durationSeconds": 3600 }
/// </summary>
api.MapPost("/bans", async (
    [FromBody] BanRequest req,
    IBanService bans,
    IAccessLogService accessLog,
    HttpContext ctx) =>
{
    var validationError = req.Validate();
    if (validationError is not null)
        return Results.BadRequest(validationError);

    var reason = req.Reason ?? "api request";
    await bans.BanAsync(req.Ip, reason, req.DurationSeconds);

    var caller = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    accessLog.LogBanAction(caller, "BAN", req.Ip);

    return Results.Ok(new { banned = req.Ip, reason, durationSeconds = req.DurationSeconds });
});

/// <summary>DELETE /api/bans/{ip} — remove a ban.</summary>
api.MapDelete("/bans/{ip}", async (
    string ip,
    IBanService bans,
    IAccessLogService accessLog,
    HttpContext ctx) =>
{
    await bans.UnbanAsync(ip);

    var caller = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    accessLog.LogBanAction(caller, "UNBAN", ip);

    return Results.Ok(new { unbanned = ip });
});

app.Run();

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// <summary>
/// Checks if an IP address is allowed based on a list of IP addresses or CIDR blocks.
/// </summary>
static bool IsIpAllowed(IPAddress remote, List<string> allowedAddresses)
{
    foreach (var allowed in allowedAddresses)
    {
        // Try exact IP match first
        if (IPAddress.TryParse(allowed, out var exactIp) && exactIp.Equals(remote))
            return true;

        // Try CIDR notation (e.g., "192.168.1.0/24")
        if (allowed.Contains('/'))
        {
            var parts = allowed.Split('/');
            if (parts.Length == 2 &&
                IPAddress.TryParse(parts[0], out var network) &&
                int.TryParse(parts[1], out var prefixLength) &&
                IsInCidrRange(remote, network, prefixLength))
            {
                return true;
            }
        }
    }

    return false;
}

/// <summary>
/// Checks if an IP address is within a CIDR range.
/// </summary>
static bool IsInCidrRange(IPAddress address, IPAddress network, int prefixLength)
{
    // Ensure both addresses are the same family
    if (address.AddressFamily != network.AddressFamily)
        return false;

    var addressBytes = address.GetAddressBytes();
    var networkBytes = network.GetAddressBytes();

    if (addressBytes.Length != networkBytes.Length)
        return false;

    var bytesToCheck = prefixLength / 8;
    var bitsToCheck = prefixLength % 8;

    // Check full bytes
    for (var i = 0; i < bytesToCheck; i++)
    {
        if (addressBytes[i] != networkBytes[i])
            return false;
    }

    // Check remaining bits
    if (bitsToCheck > 0)
    {
        var mask = (byte)(0xFF << (8 - bitsToCheck));
        if ((addressBytes[bytesToCheck] & mask) != (networkBytes[bytesToCheck] & mask))
            return false;
    }

    return true;
}
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
    return 1;
}
finally
{
    Log.Information("Shutting down frp-ban server");
    await Log.CloseAndFlushAsync();
}

return 0;
