namespace DataExfiltrationShield.ManagementAPI.Models;

public record AgentInfo
{
    public required string Id { get; init; }
    public string? Hostname { get; init; }
    public required DateTimeOffset LastSeen { get; init; }
    public string Status => DateTimeOffset.UtcNow - LastSeen < TimeSpan.FromMinutes(5) ? "online" : "stale";
}
