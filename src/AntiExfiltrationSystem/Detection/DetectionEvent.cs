using System.Net;

namespace AntiExfiltrationSystem.Detection;

public sealed record DetectionEvent(
    DateTime Timestamp,
    string ProcessName,
    IPEndPoint RemoteEndpoint,
    string ThreatLabel,
    string ActionTaken,
    double Confidence,
    IReadOnlyList<string> Indicators);
