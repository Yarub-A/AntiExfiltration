using DataExfiltrationShield.ManagementAPI.Models;

namespace DataExfiltrationShield.ManagementAPI.Services;

public interface IAgentRegistry
{
    void MarkAgentSeen(string agentId, string? hostname);
    IReadOnlyCollection<AgentInfo> ListAgents();
}
