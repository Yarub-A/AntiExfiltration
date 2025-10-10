using System.Collections.Concurrent;
using System.Text.Json;
using DataExfiltrationShield.ManagementAPI.Models;

namespace DataExfiltrationShield.ManagementAPI.Services;

public class InMemoryIncidentService : IIncidentService
{
    private readonly ConcurrentDictionary<string, Incident> _incidents = new();

    public Incident? GetIncident(string id)
    {
        return _incidents.TryGetValue(id, out var incident) ? incident : null;
    }

    public void RecordEvent(AgentEvent agentEvent)
    {
        var incidentId = $"{agentEvent.AgentId}-{agentEvent.Timestamp:yyyyMMddHHmmssfff}";
        var incident = _incidents.GetOrAdd(incidentId, _ => new Incident
        {
            Id = incidentId,
            CreatedAt = DateTimeOffset.UtcNow,
            Severity = InferSeverity(agentEvent.Type),
            ProcessId = TryParseProcessId(agentEvent.Payload)
        });

        if (agentEvent.Payload.TryGetValue("artifacts", out var artifactsElement) &&
            artifactsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var artifact in artifactsElement.EnumerateArray())
            {
                incident.Artifacts.Add(new IncidentArtifact
                {
                    Type = artifact.TryGetProperty("type", out var typeElement) && typeElement.ValueKind == JsonValueKind.String
                        ? typeElement.GetString() ?? "unknown"
                        : artifact.ToString(),
                    Location = artifact.TryGetProperty("location", out var locationElement) && locationElement.ValueKind == JsonValueKind.String
                        ? locationElement.GetString()
                        : null,
                    Hash = artifact.TryGetProperty("hash", out var hashElement) && hashElement.ValueKind == JsonValueKind.String
                        ? hashElement.GetString()
                        : null
                });
            }
        }
    }

    public IncidentAction RecordAction(QuarantineRequest request)
    {
        var action = new IncidentAction
        {
            Id = Guid.NewGuid().ToString("N"),
            Action = request.Action,
            Timestamp = DateTimeOffset.UtcNow,
            RequestedBy = request.RequestedBy,
            Reason = request.Reason
        };

        var incidentId = $"process-{request.ProcessId}";
        var incident = _incidents.GetOrAdd(incidentId, _ => new Incident
        {
            Id = incidentId,
            CreatedAt = DateTimeOffset.UtcNow,
            Severity = "medium",
            ProcessId = request.ProcessId
        });

        incident.Actions.Add(action);
        return action;
    }

    private static int? TryParseProcessId(IReadOnlyDictionary<string, JsonElement> payload)
    {
        if (payload.TryGetValue("processId", out var processElement))
        {
            if (processElement.ValueKind == JsonValueKind.Number && processElement.TryGetInt32(out var pid))
            {
                return pid;
            }

            if (processElement.ValueKind == JsonValueKind.String && int.TryParse(processElement.GetString(), out var parsed))
            {
                return parsed;
            }
        }

        return null;
    }

    private static string InferSeverity(string eventType) => eventType switch
    {
        "memory" => "high",
        "network" => "medium",
        _ => "low"
    };
}
