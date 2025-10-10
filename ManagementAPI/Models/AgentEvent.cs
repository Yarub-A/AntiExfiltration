using System.Text.Json;
using System.Text.Json.Serialization;

namespace DataExfiltrationShield.ManagementAPI.Models;

public record AgentEvent
{
    [JsonPropertyName("agentId")]
    public required string AgentId { get; init; }

    [JsonPropertyName("timestamp")]
    public required DateTimeOffset Timestamp { get; init; }

    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("payload")]
    public required Dictionary<string, JsonElement> Payload { get; init; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; init; }
}
