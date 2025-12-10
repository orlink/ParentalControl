using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ScreenPulse;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        var programDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ScreenPulse");
        var bootstrapLogPath = Path.Combine(programDataPath, "bootstrap.log");

        void LogBootstrap(string message)
        {
            var line = $"{DateTimeOffset.Now:u} {message}";
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(bootstrapLogPath)!);
                File.AppendAllText(bootstrapLogPath, line + Environment.NewLine);
            }
            catch
            {
                // ignore logging failures during bootstrap
            }

            try
            {
                Console.WriteLine(line);
            }
            catch
            {
                // ignore if no console (Windows Service)
            }
        }

        EnsureProgramDataFiles(programDataPath, AppContext.BaseDirectory, LogBootstrap);

        if ((args.Length >= 3 && args[0] == "--tray"))
        {
            RunTray(args, LogBootstrap);
            return;
        }

        var builder = Host.CreateApplicationBuilder(args);

        builder.Configuration
            .AddJsonFile("settings.json", optional: true, reloadOnChange: true)
            .AddJsonFile(Path.Combine(programDataPath, "settings.json"), optional: true, reloadOnChange: true)
            .AddEnvironmentVariables();

        builder.Services.AddWindowsService(options => options.ServiceName = "ScreenPulse");
        builder.Services.Configure<ControlSettings>(builder.Configuration.GetSection("ControlSettings"));
        builder.Services.AddSingleton(sp =>
            new UsageStore(Path.Combine(programDataPath, "usage.json"), sp.GetRequiredService<ILogger<UsageStore>>()));
        builder.Services.AddSingleton<SessionWatcher>();
        builder.Services.AddHostedService<Worker>();

        var host = builder.Build();
        Directory.CreateDirectory(programDataPath);
        host.Run();
    }

    private static void RunTray(string[] args, Action<string> log)
    {
        try
        {
            var daily = args.ElementAtOrDefault(1) ?? "00:00";
            var weekly = args.ElementAtOrDefault(2) ?? "00:00";
            var parentPid = 0;
            _ = int.TryParse(args.ElementAtOrDefault(3), out parentPid);

            log($"Starting tray host with daily={daily}, weekly={weekly}, parentPid={parentPid}");
            var thread = new Thread(() => TrayIconRunner.Run(daily, weekly, parentPid));
            thread.SetApartmentState(ApartmentState.STA);
            thread.IsBackground = false;
            thread.Start();
            thread.Join();
        }
        catch (Exception ex)
        {
            log($"Tray host failed: {ex}");
        }
    }

    private static void EnsureProgramDataFiles(string programDataPath, string contentRoot, Action<string> log)
    {
        log($"Ensuring program data at '{programDataPath}' from '{contentRoot}'");
        Directory.CreateDirectory(programDataPath);

        CopySettingsWithTargetUserIfMissing(Path.Combine(contentRoot, "settings.json"),
            Path.Combine(programDataPath, "settings.json"), log);
        CopyIfMissing(Path.Combine(contentRoot, "appsettings.Development.json"),
            Path.Combine(programDataPath, "appsettings.Development.json"), log);
    }

    private static void CopySettingsWithTargetUserIfMissing(string source, string destination, Action<string> log)
    {
        try
        {
            if (File.Exists(destination))
            {
                log($"Skip copy; destination exists: {destination}");
                return;
            }

            if (!File.Exists(source))
            {
                log($"Skip copy; source missing: {source}");
                return;
            }

            var targetUser = GetCurrentWindowsUser();
            try
            {
                var jsonObject = JsonNode.Parse(File.ReadAllText(source)) as JsonObject
                                 ?? throw new InvalidOperationException("settings json root must be an object");
                var controlSettings = jsonObject["ControlSettings"] as JsonObject ?? new JsonObject();
                controlSettings["TargetUser"] = targetUser;
                jsonObject["ControlSettings"] = controlSettings;

                File.WriteAllText(destination, jsonObject.ToJsonString(new JsonSerializerOptions
                {
                    WriteIndented = true
                }));
                log($"Copied '{source}' to '{destination}' with TargetUser '{targetUser}'");
            }
            catch (Exception parseEx)
            {
                File.Copy(source, destination);
                log($"Copied '{source}' to '{destination}' without changing TargetUser: {parseEx.Message}");
            }
        }
        catch (Exception ex)
        {
            log($"Error copying '{source}' to '{destination}': {ex.Message}");
        }
    }

    private static string GetCurrentWindowsUser()
    {
        try
        {
            var user = Environment.UserName;
            var domain = Environment.UserDomainName;

            if (string.IsNullOrWhiteSpace(user))
            {
                return user;
            }

            if (string.IsNullOrWhiteSpace(domain) || domain.Equals(user, StringComparison.OrdinalIgnoreCase))
            {
                return user;
            }

            return $"{domain}\\{user}";
        }
        catch
        {
            return Environment.UserName;
        }
    }

    private static void CopyIfMissing(string source, string destination, Action<string> log)
    {
        try
        {
            if (File.Exists(destination))
            {
                log($"Skip copy; destination exists: {destination}");
                return;
            }

            if (!File.Exists(source))
            {
                log($"Skip copy; source missing: {source}");
                return;
            }

            File.Copy(source, destination);
            log($"Copied '{source}' to '{destination}'");
        }
        catch (Exception ex)
        {
            log($"Error copying '{source}' to '{destination}': {ex.Message}");
        }
    }
}
