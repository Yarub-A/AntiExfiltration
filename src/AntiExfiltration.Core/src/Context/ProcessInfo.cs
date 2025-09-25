namespace AntiExfiltration.Core.Context;

/// <summary>
/// Snapshot of the process that initiated an outbound network flow.
/// </summary>
public sealed class ProcessInfo
{
    public required int Pid { get; init; }
    public required string Name { get; init; }
    public required string ExecutablePath { get; init; }
    public required string DigitalSignature { get; init; }
    public required int ParentPid { get; init; }
    public required bool IsSystemProcess { get; init; }
}
