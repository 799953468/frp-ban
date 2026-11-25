using FrpBan.Client.Configuration;
using FrpBan.Client.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;

// Configuration comes from appsettings.json in the content root (the working directory by default,
// /etc/frp-ban-client for the packaged service), environment variables, and command-line arguments.
var builder = Host.CreateApplicationBuilder(args);
var section = builder.Configuration.GetSection("ClientSettings");

var logging = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
    // Start-up failures are reported once, below, instead of also by the host.
    .MinimumLevel.Override("Microsoft.Extensions.Hosting.Internal.Host", LogEventLevel.Fatal)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");
if (section["AppLogPath"] is { Length: > 0 } appLogPath)
{
    logging.WriteTo.File(appLogPath, rollingInterval: RollingInterval.Day,
        rollOnFileSizeLimit: true, fileSizeLimitBytes: 104857600, retainedFileCountLimit: 30);
}

Log.Logger = logging.CreateLogger();
builder.Logging.ClearProviders();
builder.Logging.AddSerilog();

builder.Services.AddSingleton<IValidateOptions<ClientSettings>, ClientSettingsValidator>();
builder.Services.AddOptions<ClientSettings>().Bind(section).ValidateOnStart();
builder.Services.AddSingleton<ClientConnectionService>();
builder.Services.AddSingleton<BanDeliveryService>();
builder.Services.AddSingleton<RuleMatchEngine>();
builder.Services.AddSingleton<RulesLoader>();
builder.Services.AddHostedService<ClientWorker>();

try
{
    using var host = builder.Build();
    await host.RunAsync();
}
catch (OptionsValidationException ex)
{
    Log.Fatal("Invalid configuration: {Errors}", string.Join(" ", ex.Failures));
    Environment.ExitCode = 1;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Client failed to start");
    Environment.ExitCode = 1;
}
finally
{
    Log.Information("FrpBan client stopped");
    await Log.CloseAndFlushAsync();
}
