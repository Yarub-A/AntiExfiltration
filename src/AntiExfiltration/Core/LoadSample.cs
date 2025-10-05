using System.Runtime.Versioning;

namespace AntiExfiltration.Core;

[SupportedOSPlatform("windows")]
public sealed record LoadSample
{
    public required DateTimeOffset Timestamp { get; init; }
    public required double CpuPercent { get; init; }
    public required double WorkingSetMb { get; init; }
    public required double ManagedMemoryMb { get; init; }
    public required long ThreadCount { get; init; }
    public required long HandleCount { get; init; }
    public double? NetworkBytesPerSecond { get; init; }
}
