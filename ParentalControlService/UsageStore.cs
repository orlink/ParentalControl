using System.Text.Json;

namespace ParentalControlService;

public record UsageSnapshot(int DailyMinutes, int WeeklyMinutes);

public class UsageStore
{
    private readonly string _path;
    private readonly ILogger<UsageStore> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private UsageFile _state = new(new Dictionary<string, List<UsageEntry>>(StringComparer.OrdinalIgnoreCase));

    public UsageStore(string path, ILogger<UsageStore> logger)
    {
        _path = path;
        _logger = logger;
    }

    public async Task<UsageSnapshot> AddUsageAsync(string user, DateOnly today, TimeSpan delta, CancellationToken token)
    {
        if (delta <= TimeSpan.Zero)
        {
            return await GetUsageAsync(user, today, token);
        }

        await _gate.WaitAsync(token);
        try
        {
            await EnsureLoadedAsync(token);

            var minutesToAdd = (int)Math.Ceiling(delta.TotalMinutes);
            if (!_state.Users.TryGetValue(user, out var entries))
            {
                entries = new List<UsageEntry>();
                _state.Users[user] = entries;
            }

            var weekStart = GetWeekStart(today);
            entries.RemoveAll(e => e.Date < weekStart);

            var daily = entries.FirstOrDefault(e => e.Date == today);
            if (daily == null)
            {
                daily = new UsageEntry { Date = today, Minutes = 0 };
                entries.Add(daily);
            }

            daily.Minutes += minutesToAdd;

            var weeklyTotal = entries.Where(e => e.Date >= weekStart).Sum(e => e.Minutes);

            await PersistAsync(token);

            return new UsageSnapshot(daily.Minutes, weeklyTotal);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<UsageSnapshot> GetUsageAsync(string user, DateOnly today, CancellationToken token)
    {
        await _gate.WaitAsync(token);
        try
        {
            await EnsureLoadedAsync(token);
            if (_state.Users.TryGetValue(user, out var entries))
            {
                var weekStart = GetWeekStart(today);
                entries.RemoveAll(e => e.Date < weekStart);
                var daily = entries.FirstOrDefault(e => e.Date == today)?.Minutes ?? 0;
                var weekly = entries.Where(e => e.Date >= weekStart).Sum(e => e.Minutes);
                return new UsageSnapshot(daily, weekly);
            }

            return new UsageSnapshot(0, 0);
        }
        finally
        {
            _gate.Release();
        }
    }

    private static DateOnly GetWeekStart(DateOnly date)
    {
        var diff = ((int)date.DayOfWeek + 6) % 7; // Monday = start
        return date.AddDays(-diff);
    }

    private async Task EnsureLoadedAsync(CancellationToken token)
    {
        if (_state.Users.Count > 0 || !File.Exists(_path))
        {
            return;
        }

        try
        {
            await using var stream = File.OpenRead(_path);
            var loaded = await JsonSerializer.DeserializeAsync<UsageFile>(stream, cancellationToken: token);
            if (loaded != null)
            {
                _state = loaded;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read usage file, starting fresh at {File}", _path);
            _state = new UsageFile(new Dictionary<string, List<UsageEntry>>(StringComparer.OrdinalIgnoreCase));
        }
    }

    private async Task PersistAsync(CancellationToken token)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await using var stream = File.Create(_path);
            await JsonSerializer.SerializeAsync(stream, _state, cancellationToken: token, options: new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write usage file to {File}", _path);
        }
    }

    private record UsageFile(Dictionary<string, List<UsageEntry>> Users);

    private class UsageEntry
    {
        public DateOnly Date { get; set; }
        public int Minutes { get; set; }
    }
}
