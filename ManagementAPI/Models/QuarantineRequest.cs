using System.Text.Json.Serialization;

namespace DataExfiltrationShield.ManagementAPI.Models;

public record QuarantineRequest
{
    [JsonPropertyName("processId")]
    public int ProcessId { get; init; }

    [JsonPropertyName("action")]
    public QuarantineAction Action { get; init; } = QuarantineAction.NetworkQuarantine;

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("requestedBy")]
    public string? RequestedBy { get; init; }
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum QuarantineAction
{
    NetworkQuarantine,
    SoftSuspend,
    Terminate
}
