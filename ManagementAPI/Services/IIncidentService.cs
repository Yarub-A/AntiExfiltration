using DataExfiltrationShield.ManagementAPI.Models;

namespace DataExfiltrationShield.ManagementAPI.Services;

public interface IIncidentService
{
    void RecordEvent(AgentEvent agentEvent);
    Incident? GetIncident(string id);
    IncidentAction RecordAction(QuarantineRequest request);
}
