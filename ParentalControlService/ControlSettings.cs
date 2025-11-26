namespace ParentalControlService;

public class ControlSettings
{
    public string TargetUser { get; set; } = string.Empty;
    public int DailyMaxMinutes { get; set; } = 90;
    public int WeeklyMaxMinutes { get; set; } = 240;
    public int AlertMinutesBeforeLogout { get; set; } = 10;
    public int SamplingSeconds { get; set; } = 5;
    public Dictionary<string, List<TimeWindow>> AllowedWindows { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public IEnumerable<TimeWindow> GetWindowsForDay(DayOfWeek day)
    {
        var key = day.ToString();
        if (AllowedWindows.TryGetValue(key, out var windows))
        {
            return windows;
        }

        return Array.Empty<TimeWindow>();
    }
}

public class TimeWindow
{
    public string Start { get; set; } = "00:00";
    public string End { get; set; } = "23:59";

    public bool TryGetRange(out TimeSpan start, out TimeSpan end)
    {
        if (TimeSpan.TryParse(Start, out start) && TimeSpan.TryParse(End, out end) && end > start)
        {
            return true;
        }

        start = TimeSpan.Zero;
        end = TimeSpan.Zero;
        return false;
    }
}
