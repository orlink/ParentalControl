using Microsoft.Extensions.Options;

namespace ParentalControlService;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IOptionsMonitor<ControlSettings> _settings;
    private readonly SessionWatcher _sessions;
    private readonly UsageStore _usage;
    private readonly HashSet<string> _alertsSent = new();
    private DateTimeOffset _lastSample = DateTimeOffset.Now;

    public Worker(
        ILogger<Worker> logger,
        IOptionsMonitor<ControlSettings> settings,
        SessionWatcher sessions,
        UsageStore usage)
    {
        _logger = logger;
        _settings = settings;
        _sessions = sessions;
        _usage = usage;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Parental control service started");
        while (!stoppingToken.IsCancellationRequested)
        {
            var now = DateTimeOffset.Now;
            var delta = now - _lastSample;
            _lastSample = now;

            try
            {
                await EnforceAsync(now, delta, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during enforcement loop");
            }

            try
            {
                var interval = TimeSpan.FromSeconds(Math.Max(1, _settings.CurrentValue.SamplingSeconds));
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task EnforceAsync(DateTimeOffset now, TimeSpan delta, CancellationToken token)
    {
        var settings = _settings.CurrentValue;
        if (string.IsNullOrWhiteSpace(settings.TargetUser))
        {
            _logger.LogWarning("No TargetUser configured; nothing to enforce");
            return;
        }

        var session = _sessions.GetActiveSessionForUser(settings.TargetUser);
        if (session == null)
        {
            _alertsSent.Clear();
            return;
        }

        var today = DateOnly.FromDateTime(now.LocalDateTime);
        var activeWindow = TryGetActiveWindow(settings, now.LocalDateTime, out var windowEnd);
        if (!activeWindow)
        {
            _logger.LogInformation("User {User} outside allowed window, logging off", settings.TargetUser);
            _sessions.Logoff(session.SessionId);
            return;
        }

        var usage = await _usage.AddUsageAsync(settings.TargetUser, today, delta, token);
        var dailyRemaining = settings.DailyMaxMinutes - usage.DailyMinutes;
        var weeklyRemaining = settings.WeeklyMaxMinutes - usage.WeeklyMinutes;
        var windowRemaining = windowEnd.HasValue
            ? (int)Math.Floor((windowEnd.Value - now.LocalDateTime).TotalMinutes)
            : int.MaxValue;

        var smallestRemaining = new[] { dailyRemaining, weeklyRemaining, windowRemaining }.Min();

        if (smallestRemaining <= 0)
        {
            _logger.LogInformation("Usage limit reached for {User} (daily {Daily}, weekly {Weekly}, window {Window})",
                settings.TargetUser, dailyRemaining, weeklyRemaining, windowRemaining);
            _sessions.Logoff(session.SessionId);
            return;
        }

        var alertThreshold = settings.AlertMinutesBeforeLogout;
        var alertKey = $"{session.SessionId}-{today}";
        if (smallestRemaining <= alertThreshold && !_alertsSent.Contains(alertKey))
        {
            _logger.LogInformation("Sending warning to {User}, {Minutes} minutes remaining", settings.TargetUser,
                smallestRemaining);
            _sessions.SendWarning(
                session.SessionId,
                "Parental control",
                $"You will be logged out in {smallestRemaining} minute(s). Save your work.",
                TimeSpan.FromSeconds(1));
            _alertsSent.Add(alertKey);
        }
    }

    private static bool TryGetActiveWindow(ControlSettings settings, DateTime nowLocal, out DateTime? windowEnd)
    {
        foreach (var window in settings.GetWindowsForDay(nowLocal.DayOfWeek))
        {
            if (!window.TryGetRange(out var start, out var end))
            {
                continue;
            }

            var startTime = nowLocal.Date.Add(start);
            var endTime = nowLocal.Date.Add(end);
            if (nowLocal >= startTime && nowLocal < endTime)
            {
                windowEnd = endTime;
                return true;
            }
        }

        windowEnd = null;
        return false;
    }
}
