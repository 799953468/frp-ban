using System.Text.Json.Serialization;

namespace FrpBan.Models;

internal sealed record CreateBanRequest(string? Ip, string? Reason, int? DurationSeconds);

internal sealed record ManagementError(string Error);

internal sealed record BanListResponse(
    BanEntry[] Items,
    int Total,
    int Page,
    int PageSize,
    int ActiveCount,
    int PermanentCount,
    int DefaultBanDurationSeconds);

// Keep the browser API's camelCase contract separate from the persistence format.
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CreateBanRequest))]
[JsonSerializable(typeof(ManagementError))]
[JsonSerializable(typeof(BanListResponse))]
internal partial class ManagementJsonContext : JsonSerializerContext
{
}