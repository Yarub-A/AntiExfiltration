using AntiExfiltrationSystem.Detection;

namespace AntiExfiltrationSystem.Core;

public sealed record SystemStatistics(
    long PacketsInspected,
    long BlockedConnections,
    long ProcessesTracked,
    long MemoryScans,
    long ConfirmedThreats,
    IReadOnlyList<DetectionEvent> RecentDetections);
