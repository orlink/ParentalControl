using System.Runtime.InteropServices;

namespace ParentalControlService;

public record UserSession(int SessionId, string UserName, bool IsActive);

public class SessionWatcher
{
    private readonly ILogger<SessionWatcher> _logger;

    public SessionWatcher(ILogger<SessionWatcher> logger)
    {
        _logger = logger;
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
        WTSConnectState
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

    #endregion
}
