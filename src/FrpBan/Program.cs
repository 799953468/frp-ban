using FrpBan.Configuration;
using FrpBan.Endpoints;
using FrpBan.Handlers;
using FrpBan.Security;
using FrpBan.Services;
using Serilog;
using Serilog.Events;

// -------------------------------------------------------------------------
// Configuration Loading
// -------------------------------------------------------------------------
var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Load PluginSettings to get log path
var pluginSettings = config.GetSection("PluginSettings").Get<PluginSettings>() ?? new PluginSettings();

// Get log level from configuration (default: Information)
var logLevel = config.GetValue<string>("Logging:LogLevel:Default", "Information");
var minLogLevel = logLevel.ToLowerInvariant() switch
{
    "debug" => LogEventLevel.Debug,
    "information" => LogEventLevel.Information,
    "warning" => LogEventLevel.Warning,
    "error" => LogEventLevel.Error,
    _ => LogEventLevel.Information
};

// -------------------------------------------------------------------------
// Serilog Configuration (hardcoded, only path and level from config)
// -------------------------------------------------------------------------
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Is(minLogLevel)
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.AspNetCore.Hosting", LogEventLevel.Information)
    .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Async(a => a.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}"
    ))
    .WriteTo.Async(a => a.File(
        path: pluginSettings.AppLogPath,
        rollingInterval: RollingInterval.Day,
        rollOnFileSizeLimit: true,
        fileSizeLimitBytes: 104857600, // 100MB
        retainedFileCountLimit: 30,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
        restrictedToMinimumLevel: minLogLevel
    ), bufferSize: 10000, blockWhenFull: false)
    .CreateLogger();

try
{
    Log.Information("Starting frp-ban server");

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
    builder.Services.AddSingleton<PluginRequestHandler>();
    builder.Services.AddSingleton<PluginAddressFilter>();
    builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 65536);
    builder.Services.AddHostedService<TcpServerService>();

    await using var app = builder.Build();

    // Load persisted bans before accepting traffic.
    app.Services.GetRequiredService<BanService>().Load();

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

    // -------------------------------------------------------------------------
    // Routes — frps plugin endpoint (ONLY)
    // -------------------------------------------------------------------------

    app.MapPluginEndpoints();

    await app.RunAsync();
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
