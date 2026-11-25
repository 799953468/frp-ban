using System.Text.Json.Serialization;

namespace FrpBan.Protocol;

/// <summary>Outcome of a ban request, shared by the server ban store and the wire protocol.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<BanStatus>))]
public enum BanStatus
{
    /// <summary>The ban was added or extended and has been persisted.</summary>
    Applied = 1,

    /// <summary>An equal or stronger ban already exists and has been persisted.</summary>
    AlreadyBanned = 2,

    /// <summary>The address is exempt by server configuration. Terminal.</summary>
    Exempt = 3,

    /// <summary>The IP address, reason, or duration is invalid. Terminal.</summary>
    Invalid = 4,

    /// <summary>The server has reached its configured ban capacity. Terminal.</summary>
    CapacityReached = 5,

    /// <summary>The ban is active in server memory but is not yet persisted. Retry later.</summary>
    StorageUnavailable = 6,
}

/// <summary>Classifies ban outcomes for callers that only need success or retry decisions.</summary>
public static class BanStatusExtensions
{
    /// <summary>True when the address is banned and the ban is durable.</summary>
    public static bool IsSuccess(this BanStatus status) => status is BanStatus.Applied or BanStatus.AlreadyBanned;

    /// <summary>True when repeating the same request later may succeed.</summary>
    public static bool IsRetryable(this BanStatus status) => status is BanStatus.StorageUnavailable;
}
