using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;
using AntiExfiltration.Core.Logging;

namespace AntiExfiltration.Core.Action;

/// <summary>
/// Orchestrates concrete enforcement actions (blocking, obfuscation, process kill).
/// The actual low-level implementations are injected to preserve testability.
/// </summary>
public sealed class ActionExecutor : IEnforcementAction
{
    private readonly IPacketDropper _packetDropper;
    private readonly IDataObfuscator _dataObfuscator;
    private readonly IProcessTerminator _processTerminator;
    private readonly IEventLogger _logger;

    public ActionExecutor(
        IPacketDropper packetDropper,
        IDataObfuscator dataObfuscator,
        IProcessTerminator processTerminator,
        IEventLogger logger)
    {
        _packetDropper = packetDropper;
        _dataObfuscator = dataObfuscator;
        _processTerminator = processTerminator;
        _logger = logger;
    }

    public void Execute(Decision decision, RawPacket packet, ProcessInfo process, CancellationToken cancellationToken = default)
    {
        switch (decision)
        {
            case Decision.Allow:
                _logger.LogAllow(packet, process);
                break;
            case Decision.Block:
                _packetDropper.Drop(packet);
                _logger.LogBlock(packet, process);
                break;
            case Decision.Obfuscate:
                _dataObfuscator.Obfuscate(packet);
                _logger.LogObfuscation(packet, process);
                break;
            case Decision.Alert:
                _logger.LogAlert(packet, process);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(decision), decision, "Unsupported decision type");
        }

        if (decision == Decision.Block && !process.IsSystemProcess)
        {
            _processTerminator.Terminate(process);
        }
    }
}

public interface IPacketDropper
{
    void Drop(RawPacket packet);
}

public interface IDataObfuscator
{
    void Obfuscate(RawPacket packet);
}

public interface IProcessTerminator
{
    void Terminate(ProcessInfo processInfo);
}
