namespace DataExfiltrationShield.ManagementAPI.Models;

public record Incident
{
    public required string Id { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required string Severity { get; init; }
    public int? ProcessId { get; init; }
    public List<IncidentArtifact> Artifacts { get; init; } = new();
    public List<IncidentAction> Actions { get; init; } = new();
}

public record IncidentArtifact
{
    public required string Type { get; init; }
    public string? Location { get; init; }
    public string? Hash { get; init; }
}

public record IncidentAction
{
    public required string Id { get; init; }
    public required QuarantineAction Action { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public string? RequestedBy { get; init; }
    public string? Reason { get; init; }
}
