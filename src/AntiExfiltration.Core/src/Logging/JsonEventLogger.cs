using System.Text.Json;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Context;

namespace AntiExfiltration.Core.Logging;

/// <summary>
/// Persists events into a JSON lines file, enabling easy ingestion into SIEM pipelines.
/// </summary>
public sealed class JsonEventLogger : IEventLogger
{
    private readonly string _logFilePath;
    private readonly JsonSerializerOptions _serializerOptions;
    private readonly object _sync = new();

    public JsonEventLogger(string logFilePath)
    {
        _logFilePath = logFilePath;
        _serializerOptions = new JsonSerializerOptions
        {
            WriteIndented = false
        };
    }

    public void LogAllow(RawPacket packet, ProcessInfo processInfo) => Log("ALLOW", packet, processInfo);
    public void LogBlock(RawPacket packet, ProcessInfo processInfo) => Log("BLOCK", packet, processInfo);
    public void LogObfuscation(RawPacket packet, ProcessInfo processInfo) => Log("OBFUSCATE", packet, processInfo);
    public void LogAlert(RawPacket packet, ProcessInfo processInfo) => Log("ALERT", packet, processInfo);

    private void Log(string action, RawPacket packet, ProcessInfo processInfo)
    {
        var entry = new
        {
            action,
            timestamp = DateTimeOffset.UtcNow,
            process = new { processInfo.Pid, processInfo.Name, processInfo.ExecutablePath, processInfo.DigitalSignature },
            destination = packet.Destination.ToString(),
            protocol = packet.Protocol.ToString(),
            payloadSize = packet.Payload.Length
        };

        var line = JsonSerializer.Serialize(entry, _serializerOptions);
        lock (_sync)
        {
            File.AppendAllText(_logFilePath, line + Environment.NewLine);
        }
    }
}
