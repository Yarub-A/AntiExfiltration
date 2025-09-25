namespace AntiExfiltration.Core.Context;

/// <summary>
/// Provides metadata about the process that owns an outbound network operation.
/// </summary>
public interface IProcessContextResolver
{
    ProcessInfo Resolve(int processId);
}
