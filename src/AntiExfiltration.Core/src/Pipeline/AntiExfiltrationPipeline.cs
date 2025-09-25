using AntiExfiltration.Core.Action;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Decision;
using AntiExfiltration.Core.Policy;

namespace AntiExfiltration.Core.Pipeline;

/// <summary>
/// Central coordinator that wires all modules according to the reference architecture.
/// </summary>
public sealed class AntiExfiltrationPipeline
{
    private readonly ICaptureProvider _captureProvider;
    private readonly PolicyEngine _policyEngine;
    private readonly DecisionEngine _decisionEngine;
    private readonly IEnforcementAction _enforcementAction;

    public AntiExfiltrationPipeline(
        ICaptureProvider captureProvider,
        PolicyEngine policyEngine,
        DecisionEngine decisionEngine,
        IEnforcementAction enforcementAction)
    {
        _captureProvider = captureProvider;
        _policyEngine = policyEngine;
        _decisionEngine = decisionEngine;
        _enforcementAction = enforcementAction;
    }

    public void Start()
    {
        _captureProvider.PacketCaptured += OnPacketCaptured;
        _captureProvider.Start();
    }

    private void OnPacketCaptured(object? sender, RawPacket packet)
    {
        var analysis = _policyEngine.Analyze(packet);
        var decision = _decisionEngine.Decide(analysis);
        _enforcementAction.Execute(decision, packet, analysis.Process);
    }
}
