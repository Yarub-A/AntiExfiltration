using System.Collections.Concurrent;
using DataExfiltrationShield.ManagementAPI.Models;

namespace DataExfiltrationShield.ManagementAPI.Services;

public class InMemoryAgentRegistry : IAgentRegistry
{
    private readonly ConcurrentDictionary<string, AgentInfo> _agents = new();

    public IReadOnlyCollection<AgentInfo> ListAgents() => _agents.Values
        .OrderByDescending(agent => agent.LastSeen)
        .ToArray();

    public void MarkAgentSeen(string agentId, string? hostname)
    {
        var info = new AgentInfo
        {
            Id = agentId,
            Hostname = hostname,
            LastSeen = DateTimeOffset.UtcNow
        };
        _agents.AddOrUpdate(agentId, info, (_, _) => info);
    }
}
