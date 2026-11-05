namespace FrpBan.Services;

/// <summary>
/// Writes structured access log entries in a format parseable by fail2ban.
/// </summary>
public interface IAccessLogService
{
    /// <summary>Logs an unauthorised API access attempt (wrong or missing token).</summary>
    void LogUnauthorized(string remoteIp, string path, string method);

    /// <summary>Logs a successful ban/unban action for audit purposes.</summary>
    void LogBanAction(string remoteIp, string action, string targetIp);
}
