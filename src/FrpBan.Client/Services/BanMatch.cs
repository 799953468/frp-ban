namespace FrpBan.Client.Services;

/// <summary>A ban requested by a rule match.</summary>
/// <param name="Ip">Canonical IP address.</param>
/// <param name="DurationSeconds">Ban duration; 0 is permanent, null uses the server default.</param>
/// <param name="Reason">Reason sent to the server.</param>
public sealed record BanMatch(string Ip, int? DurationSeconds, string Reason);
