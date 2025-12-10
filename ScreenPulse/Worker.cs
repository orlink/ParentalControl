using Microsoft.Extensions.Options;

namespace ScreenPulse;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IOptionsMonitor<ControlSettings> _settings;
    private readonly SessionWatcher _sessions;
    private readonly UsageStore _usage;
    private readonly HashSet<string> _alertsSent = new();
    private DateTimeOffset _lastSample = DateTimeOffset.Now;
    private string? _lastStatusKey;
    private bool _wasLocked;

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
        _logger.LogInformation("ScreenPulse service started now");
        try
        {
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
        finally
        {
            _sessions.StopAllStatusTrays();
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
            _lastStatusKey = null;
            _wasLocked = false;
            return;
        }

        if (_sessions.IsSessionLocked(session.SessionId))
        {
            if (!_wasLocked)
            {
                _logger.LogInformation("Session {SessionId} is locked; skipping usage accumulation", session.SessionId);
            }
            _wasLocked = true;
            _alertsSent.Clear();
            _lastStatusKey = null;
            _sessions.StopStatusTray(session.SessionId);
            return;
        }

        _wasLocked = false;
        var today = DateOnly.FromDateTime(now.LocalDateTime);
        var activeWindow = TryGetActiveWindow(settings, now.LocalDateTime, out var windowEnd);
        if (!activeWindow)
        {
            _logger.LogInformation("User {User} outside allowed window, locking session", settings.TargetUser);
            _sessions.StopStatusTray(session.SessionId);
            _sessions.Lock(session.SessionId);
            return;
        }
        var usage = await _usage.AddUsageAsync(settings.TargetUser, today, delta, token, settings);
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
            _sessions.StopStatusTray(session.SessionId);
            _sessions.Lock(session.SessionId);
            return;
        }

        var thresholds = settings.NotifyMinutesBeforeLockout?
            .Where(m => m > 0)
            .Distinct()
            .OrderByDescending(m => m)
            .ToArray() ?? Array.Empty<int>();
        foreach (var threshold in thresholds)
        {
            var alertKey = $"{session.SessionId}-{today}-{threshold}";
            if (smallestRemaining <= threshold && !_alertsSent.Contains(alertKey))
            {
                var roundedMinutes = Math.Max(0, (int)Math.Round(smallestRemaining, MidpointRounding.AwayFromZero));
                _logger.LogInformation("Sending warning to {User}, {Minutes} minutes remaining (threshold {Threshold})",
                    settings.TargetUser, roundedMinutes, threshold);
                
                _sessions.SendTrayNotification(
                    session.SessionId,
                    "Usage limit",
                    $"You have {roundedMinutes} more minute(s).",
                    TimeSpan.FromSeconds(10));
                _alertsSent.Add(alertKey);
                break; // only send one notification per check cycle
            }
        }

        // var dailyRemainingMinutes = Math.Max(0, (int)Math.Round(dailyRemaining, MidpointRounding.AwayFromZero));
        // var weeklyRemainingMinutes = Math.Max(0, (int)Math.Round(weeklyRemaining, MidpointRounding.AwayFromZero));
        dailyRemaining = dailyRemaining > windowRemaining ? windowRemaining : dailyRemaining;
        dailyRemaining = dailyRemaining > weeklyRemaining ? weeklyRemaining : dailyRemaining;
        var dailyRemainingMinutes = Math.Max(0, (int)dailyRemaining);
        var weeklyRemainingMinutes = Math.Max(0, (int)weeklyRemaining);
        var frequency = dailyRemaining < 10 || weeklyRemaining < 10 ? 1 : 5;

        var statusKey = $"{session.SessionId}-{weeklyRemainingMinutes}";
        
        if (_lastStatusKey == null || (_lastStatusKey != statusKey && weeklyRemainingMinutes%frequency == 0))
        {
            _sessions.EnsureStatusTray(
                session.SessionId,
                FormatMinutes(dailyRemainingMinutes),
                FormatMinutes(weeklyRemainingMinutes));
            _lastStatusKey = statusKey;
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

    private static string FormatMinutes(int minutes)
    {
        if (minutes < 0)
        {
            minutes = 0;
        }

        var hours = minutes / 60;
        var mins = minutes % 60;
        return $"{hours:D2}:{mins:D2}";
    }
}
