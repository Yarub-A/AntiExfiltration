using System.Diagnostics;
using System.Net;

namespace AntiExfiltrationSystem.ProcessMonitoring;

public sealed class ProcessContext
{
    public required Process RootProcess { get; init; }
    public required IReadOnlyList<Process> ParentChain { get; init; }
    public required IReadOnlyList<Process> ChildProcesses { get; init; }
    public required IReadOnlyList<NetworkConnection> NetworkConnections { get; init; }
    public required SignatureStatus Signature { get; init; }
}

public sealed class NetworkConnection
{
    public required IPEndPoint LocalEndpoint { get; init; }
    public required IPEndPoint RemoteEndpoint { get; init; }
    public required string Protocol { get; init; }
    public required string State { get; init; }
    public required long BytesTransferred { get; init; }
    public required DateTime EstablishedAt { get; init; }
}

public sealed class SignatureStatus
{
    public required bool IsSigned { get; init; }
    public required bool IsTrusted { get; init; }
    public required string Subject { get; init; }
}
