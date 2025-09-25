using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Logging;

/// <summary>
/// Unified logging surface that stores events for retrospective analysis and forensics.
/// </summary>
public interface IEventLogger
{
    void LogAllow(RawPacket packet, ProcessInfo processInfo);
    void LogBlock(RawPacket packet, ProcessInfo processInfo);
    void LogObfuscation(RawPacket packet, ProcessInfo processInfo);
    void LogAlert(RawPacket packet, ProcessInfo processInfo);
}
