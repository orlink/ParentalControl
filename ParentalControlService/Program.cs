using Microsoft.Extensions.Configuration;
using ParentalControlService;

var programDataPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "ParentalControl");

var builder = Host.CreateApplicationBuilder(args);

builder.Configuration
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddJsonFile(Path.Combine(programDataPath, "settings.json"), optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.AddWindowsService(options => options.ServiceName = "ParentalControlService");
builder.Services.Configure<ControlSettings>(builder.Configuration.GetSection("ControlSettings"));
builder.Services.AddSingleton(sp =>
    new UsageStore(Path.Combine(programDataPath, "usage.json"), sp.GetRequiredService<ILogger<UsageStore>>()));
builder.Services.AddSingleton<SessionWatcher>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
Directory.CreateDirectory(programDataPath);
host.Run();
