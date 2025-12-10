using System.Diagnostics;
using System.Windows.Forms;

namespace ScreenPulse;

public static class TrayIconRunner
{
    public static void Run(string dailyRemaining, string weeklyRemaining, int parentPid)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        using var icon = new NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Information,
            Visible = true,
            Text = "ScreenPulse"
        };

        var tip = $"Today: {dailyRemaining}{Environment.NewLine}This week: {weeklyRemaining}";

        void ShowTip()
        {
            icon.BalloonTipTitle = "Screen time left:";
            icon.BalloonTipText = tip;
            icon.BalloonTipIcon = ToolTipIcon.Info;
            icon.ShowBalloonTip(5000);
        }

        icon.Click += (_, _) => ShowTip();

        //ShowTip();

        System.Windows.Forms.Timer? parentTimer = null;
        if (parentPid > 0)
        {
            parentTimer = new System.Windows.Forms.Timer { Interval = 5000 };
            parentTimer.Tick += (_, _) =>
            {
                if (!IsParentProcessAlive(parentPid))
                {
                    Quit(icon, parentTimer);
                }
            };
            parentTimer.Start();
        }

        var lifetime = new System.Windows.Forms.Timer { Interval = 3600000 };
        lifetime.Tick += (_, _) => Quit(icon, parentTimer, lifetime);
        lifetime.Start();

        Application.Run();
    }

    private static bool IsParentProcessAlive(int parentPid)
    {
        try
        {
            var proc = Process.GetProcessById(parentPid);
            try
            {
                return !proc.HasExited;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Access denied when the parent runs as SYSTEM; assume it is still alive.
                return true;
            }
            catch
            {
                // Any other failure to inspect is treated as alive to keep the tray running.
                return true;
            }
        }
        catch (ArgumentException)
        {
            // No such process.
            return false;
        }
        catch
        {
            // If we cannot query, err on the side of keeping the tray alive.
            return true;
        }
    }

    private static void Quit(NotifyIcon icon, params System.Windows.Forms.Timer[] timers)
    {
        foreach (var timer in timers)
        {
            if (timer == null)
            {
                continue;
            }
            timer.Stop();
            timer.Dispose();
        }

        icon.Visible = false;
        icon.Dispose();
        Application.Exit();
    }
}
