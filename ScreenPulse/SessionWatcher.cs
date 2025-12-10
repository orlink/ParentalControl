using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace ScreenPulse;

public record UserSession(int SessionId, string UserName, bool IsActive);

public class SessionWatcher
{
    private readonly ILogger<SessionWatcher> _logger;
    private readonly object _trayLock = new();
    private readonly Dictionary<int, int> _statusTrayProcesses = new();
    private readonly string _trayExecutable;
    private const string LockScreenProcess = "LogonUI";
    private const int WtsSessionStateLock = 0x1;
    private const int WtsSessionStateUnlock = 0x2;

    public SessionWatcher(ILogger<SessionWatcher> logger)
    {
        _logger = logger;
        _trayExecutable = Path.Combine(AppContext.BaseDirectory, "ScreenPulse.exe");
    }

    public bool IsSessionLocked(int sessionId)
    {
        if (TryGetSessionLockState(sessionId, out var locked))
        {
            return locked;
        }

        try
        {
            return Process.GetProcessesByName(LockScreenProcess)
                .Any(p => p.SessionId == sessionId && !p.HasExited);
        }
        catch
        {
            // If we cannot determine state, assume locked to avoid counting time incorrectly.
            return true;
        }
    }

    public UserSession? GetActiveSessionForUser(string user)
    {
        if (string.IsNullOrWhiteSpace(user))
        {
            return null;
        }

        var normalized = user.Trim();

        foreach (var session in EnumerateSessions())
        {
            if (session.UserName.Equals(normalized, StringComparison.OrdinalIgnoreCase) ||
                session.UserName.Split('\\').Last()
                    .Equals(normalized, StringComparison.OrdinalIgnoreCase))
            {
                return session;
            }
        }

        return null;
    }

    public void Logoff(int sessionId)
    {
        _logger.LogWarning("Logging off session {SessionId}", sessionId);
        if (!WTSLogoffSession(IntPtr.Zero, sessionId, false))
        {
            _logger.LogError("Failed to log off session {SessionId}. Error: {Error}", sessionId,
                Marshal.GetLastWin32Error());
        }
    }

    public void Lock(int sessionId)
    {
        // Disconnecting an interactive console session shows the standard Windows lock screen without logging the user out.
        _logger.LogWarning("Locking session {SessionId}", sessionId);
        if (!WTSDisconnectSession(IntPtr.Zero, sessionId, false))
        {
            _logger.LogError("Failed to lock session {SessionId}. Error: {Error}", sessionId,
                Marshal.GetLastWin32Error());
        }
    }

    public void SendWarning(int sessionId, string title, string message, TimeSpan displayTime)
    {
        const int flags = 0x00000030; // MB_ICONEXCLAMATION | MB_OK
        var response = 0;
        var timeoutSeconds = (int)Math.Max(1, Math.Ceiling(displayTime.TotalSeconds));
        var sent = WTSSendMessage(
            IntPtr.Zero,
            sessionId,
            title,
            title.Length * 2,
            message,
            message.Length * 2,
            flags,
            timeoutSeconds,
            out response,
            false);

        if (!sent)
        {
            _logger.LogWarning("Failed to send warning to session {SessionId}. Error: {Error}", sessionId,
                Marshal.GetLastWin32Error());
        }
    }

    public void StopStatusTray(int sessionId)
    {
        lock (_trayLock)
        {
            if (_statusTrayProcesses.TryGetValue(sessionId, out var pid))
            {
                try
                {
                    var proc = Process.GetProcessById(pid);
                    if (!proc.HasExited)
                    {
                        proc.Kill(true);
                    }
                }
                catch
                {
                    // ignore if already exited or not found
                }

                _statusTrayProcesses.Remove(sessionId);
            }
        }
    }

    public void StopAllStatusTrays()
    {
        int[] pids;
        lock (_trayLock)
        {
            pids = _statusTrayProcesses.Values.ToArray();
            _statusTrayProcesses.Clear();
        }

        foreach (var pid in pids)
        {
            TerminateProcessIfExists(pid);
        }
    }

    public void SendTrayNotification(int sessionId, string title, string message, TimeSpan displayTime)
    {
        _logger.LogInformation("Sending tray notification to session {SessionId}", sessionId);

        if (!TryAcquireUserToken(sessionId, out var userToken))
        {
            return;
        }

        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        try
        {
            if (!DuplicateTokenEx(
                    userToken,
                    TOKEN_ALL_ACCESS,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary,
                    out primaryToken))
            {
                _logger.LogWarning("Unable to duplicate token for session {SessionId}. Error: {Error}", sessionId,
                    Marshal.GetLastWin32Error());
                return;
            }

            if (!CreateEnvironmentBlock(out environment, primaryToken, false))
            {
                _logger.LogWarning("Unable to create environment block for session {SessionId}. Error: {Error}", sessionId,
                    Marshal.GetLastWin32Error());
                return;
            }

            var shellPath = GetPowerShellPath();
            if (shellPath == null)
            {
                _logger.LogWarning("Unable to find PowerShell for session {SessionId}; tray notification skipped", sessionId);
                return;
            }

            var commandLine = BuildTrayCommand(shellPath, title, message, displayTime);
            var startup = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = "winsta0\\default"
            };

            if (!CreateProcessAsUser(
                    primaryToken,
                    shellPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environment,
                    null,
                    ref startup,
                    out var processInfo))
            {
                _logger.LogWarning("Failed to launch notification process for session {SessionId}. Error: {Error}",
                    sessionId, Marshal.GetLastWin32Error());
                return;
            }

            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
        }
        finally
        {
            if (environment != IntPtr.Zero)
            {
                DestroyEnvironmentBlock(environment);
            }

            if (primaryToken != IntPtr.Zero)
            {
                CloseHandle(primaryToken);
            }

            if (userToken != IntPtr.Zero)
            {
                CloseHandle(userToken);
            }
        }
    }

    public void EnsureStatusTray(int sessionId, string dailyRemaining, string weeklyRemaining)
    {
        _logger.LogInformation("Ensuring status tray for session {SessionId}", sessionId);

        if (!TryAcquireUserToken(sessionId, out var userToken))
        {
            return;
        }

        if (!File.Exists(_trayExecutable))
        {
            _logger.LogWarning("Tray executable not found at {Path}", _trayExecutable);
            return;
        }

        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        try
        {
            if (!DuplicateTokenEx(
                    userToken,
                    TOKEN_ALL_ACCESS,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary,
                    out primaryToken))
            {
                _logger.LogWarning("Unable to duplicate token for session {SessionId}. Error: {Error}", sessionId,
                    Marshal.GetLastWin32Error());
                return;
            }

            if (!CreateEnvironmentBlock(out environment, primaryToken, false))
            {
                _logger.LogWarning("Unable to create environment block for session {SessionId}. Error: {Error}", sessionId,
                    Marshal.GetLastWin32Error());
                return;
            }

            var commandLine = BuildStatusTrayCommand(_trayExecutable, dailyRemaining, weeklyRemaining, Process.GetCurrentProcess().Id);
            var startup = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = "winsta0\\default"
            };

            int previousPid = 0;
            lock (_trayLock)
            {
                if (_statusTrayProcesses.TryGetValue(sessionId, out var existingPid))
                {
                    previousPid = existingPid;
                }
            }

            TerminateProcessIfExists(previousPid);

            if (!CreateProcessAsUser(
                    primaryToken,
                    _trayExecutable,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environment,
                    null,
                    ref startup,
                    out var processInfo))
            {
                _logger.LogWarning("Failed to launch status tray for session {SessionId}. Error: {Error}",
                    sessionId, Marshal.GetLastWin32Error());
                return;
            }

            var pid = processInfo.dwProcessId;
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);

            lock (_trayLock)
            {
                _statusTrayProcesses[sessionId] = pid;
            }
        }
        finally
        {
            if (environment != IntPtr.Zero)
            {
                DestroyEnvironmentBlock(environment);
            }

            if (primaryToken != IntPtr.Zero)
            {
                CloseHandle(primaryToken);
            }

            if (userToken != IntPtr.Zero)
            {
                CloseHandle(userToken);
            }
        }
    }

    private static void TerminateProcessIfExists(int pid)
    {
        if (pid <= 0)
        {
            return;
        }

        try
        {
            var proc = Process.GetProcessById(pid);
            if (!proc.HasExited)
            {
                proc.Kill(true);
            }
        }
        catch
        {
            // ignore if already gone
        }
    }

    private static string? GetPowerShellPath()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var path = Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe");
        return File.Exists(path) ? path : null;
    }

    private static string BuildTrayCommand(string shellPath, string title, string message, TimeSpan displayTime)
    {
        var safeTitle = EscapeForPowerShell(title);
        var safeMessage = EscapeForPowerShell(message);
        var milliseconds = Math.Max(1000, (int)displayTime.TotalMilliseconds);
        var sleepSeconds = Math.Max(3, (int)Math.Ceiling(displayTime.TotalSeconds) + 1);

        // Show a balloon tip from the notification area without stealing focus.
        return
            $"\\\"{shellPath}\\\" -NoProfile -WindowStyle Hidden -Command \"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Information; $n.Visible = $true; $n.BalloonTipTitle=\\\"{safeTitle}\\\"; $n.BalloonTipText=\\\"{safeMessage}\\\"; $n.BalloonTipIcon=[System.Windows.Forms.ToolTipIcon]::Warning; $n.ShowBalloonTip({milliseconds}); Start-Sleep {sleepSeconds}; $n.Dispose();\"";
    }

    private static string BuildStatusTrayCommand(string trayExe, string dailyRemaining, string weeklyRemaining, int parentPid)
    {
        var argsDaily = dailyRemaining.Replace("\"", "\\\"");
        var argsWeekly = weeklyRemaining.Replace("\"", "\\\"");
        return $"\\\"{trayExe}\\\" --tray \\\"{argsDaily}\\\" \\\"{argsWeekly}\\\" {parentPid}";
    }

    private static string EscapeForPowerShell(string value) =>
        string.IsNullOrEmpty(value) ? string.Empty : value.Replace("`", "``").Replace("\"", "`\"");

    private bool TryAcquireUserToken(int sessionId, out IntPtr userToken)
    {
        userToken = IntPtr.Zero;

        if (WTSQueryUserToken(sessionId, out userToken) && userToken != IntPtr.Zero)
        {
            return true;
        }

        var error = Marshal.GetLastWin32Error();

        // Fallback to the current process token when running as the same interactive user (e.g., during development).
        try
        {
            using var current = Process.GetCurrentProcess();
            if (current.SessionId == sessionId &&
                OpenProcessToken(current.Handle, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, out userToken) &&
                userToken != IntPtr.Zero)
            {
                _logger.LogInformation("Using current process token for tray notification in session {SessionId}", sessionId);
                return true;
            }
        }
        catch
        {
            // ignored; fall through to failure log
        }

        if (userToken != IntPtr.Zero)
        {
            CloseHandle(userToken);
            userToken = IntPtr.Zero;
        }

        _logger.LogWarning("Unable to query user token for session {SessionId}. Error: {Error}", sessionId, error);
        return false;
    }

    private bool TryGetSessionLockState(int sessionId, out bool isLocked)
    {
        isLocked = false;
        // WTSSessionInfoEx is available on Windows Vista+ and exposes SessionFlags (locked/unlocked).
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTS_INFO_CLASS.WTSSessionInfoEx, out var buffer, out var bytesReturned) ||
            bytesReturned < 24) // minimum size to read SessionFlags
        {
            return false;
        }

        try
        {
            var level = Marshal.ReadInt32(buffer); // should be 1
            if (level != 1)
            {
                return false;
            }

            // Layout: DWORD Level; DWORD Reserved; then WTSINFOEX_LEVEL1 starts with SessionId (DWORD),
            // SessionState (DWORD), SessionFlags (DWORD).
            var sessionFlags = Marshal.ReadInt32(buffer, 16);
            if (sessionFlags == WtsSessionStateLock)
            {
                isLocked = true;
                return true;
            }

            if (sessionFlags == WtsSessionStateUnlock)
            {
                isLocked = false;
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private IEnumerable<UserSession> EnumerateSessions()
    {
        var sessions = new List<UserSession>();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            _logger.LogWarning("WTSEnumerateSessions failed with error {Error}", Marshal.GetLastWin32Error());
            return sessions;
        }

        var dataSize = Marshal.SizeOf<WTS_SESSION_INFO>();
        try
        {
            for (var i = 0; i < count; i++)
            {
                var current = IntPtr.Add(buffer, i * dataSize);
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);

                var state = info.State;
                if (state != WTS_CONNECTSTATE_CLASS.WTSActive && state != WTS_CONNECTSTATE_CLASS.WTSConnected)
                {
                    continue;
                }

                var userName = QuerySessionString(info.SessionID, WTS_INFO_CLASS.WTSUserName);
                var domain = QuerySessionString(info.SessionID, WTS_INFO_CLASS.WTSDomainName);
                var composed = string.IsNullOrWhiteSpace(domain) ? userName : $"{domain}\\{userName}";

                if (!string.IsNullOrWhiteSpace(composed))
                {
                    sessions.Add(new UserSession(info.SessionID, composed, state == WTS_CONNECTSTATE_CLASS.WTSActive));
                }
            }
        }
        finally
        {
            WTSFreeMemory(buffer);
        }

        return sessions;
    }

    private static string QuerySessionString(int sessionId, WTS_INFO_CLASS infoClass)
    {
        var str = string.Empty;
        if (WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out var bytesReturned) &&
            bytesReturned > 1)
        {
            try
            {
                str = Marshal.PtrToStringAnsi(buffer) ?? string.Empty;
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }

        return str;
    }

    #region Native

    private enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }

    private enum WTS_INFO_CLASS
    {
        WTSInitialProgram,
        WTSApplicationName,
        WTSWorkingDirectory,
        WTSOEMId,
        WTSSessionId,
        WTSUserName,
        WTSWinStationName,
        WTSDomainName,
        WTSConnectState,
        WTSSessionInfoEx = 24
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionID;
        public string pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(
        IntPtr hServer,
        int reserved,
        int version,
        out IntPtr ppSessionInfo,
        out int pCount);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pointer);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        int sessionId,
        WTS_INFO_CLASS wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSLogoffSession(
        IntPtr hServer,
        int sessionId,
        bool wait);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSDisconnectSession(
        IntPtr hServer,
        int sessionId,
        bool wait);

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int sessionId, out IntPtr token);

    [DllImport("Wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSSendMessage(
        IntPtr hServer,
        int sessionId,
        string pTitle,
        int titleLength,
        string pMessage,
        int messageLength,
        int style,
        int timeout,
        out int pResponse,
        bool wait);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr existingToken,
        uint desiredAccess,
        IntPtr tokenAttributes,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel,
        TOKEN_TYPE tokenType,
        out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        int dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    private const uint TOKEN_ALL_ACCESS = 0xF01FF;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int CREATE_NO_WINDOW = 0x08000000;

    #endregion
}
