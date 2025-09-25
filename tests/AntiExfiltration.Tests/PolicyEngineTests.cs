using System.Collections.Generic;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Common;
using AntiExfiltration.Core.Context;
using AntiExfiltration.Core.Policy;
using Xunit;

namespace AntiExfiltration.Tests;

public class PolicyEngineTests
{
    [Fact]
    public void Analyze_AggregatesSignalsAndFindings()
    {
        var processResolver = new StaticProcessResolver();
        var analyzers = new IAnalyzer[]
        {
            new StubAnalyzer("A", isSensitive: false, RiskLevel.Low, "benign", new Dictionary<string, object?>
            {
                ["size"] = 42
            }),
            new StubAnalyzer("B", isSensitive: true, RiskLevel.High, "match", new Dictionary<string, object?>
            {
                ["indicator"] = "IOC123"
            })
        };
        var engine = new PolicyEngine(analyzers, processResolver);
        var packet = new RawPacket(Array.Empty<byte>(), DummyEndPoint(), DummyEndPoint(), ProtocolType.Http, 200, DateTimeOffset.UtcNow);

        var result = engine.Analyze(packet);

        Assert.True(result.IsSensitive);
        Assert.Equal(RiskLevel.High, result.Risk);
        Assert.Equal("match", result.Reason);
        Assert.Equal(2, result.Findings.Count);
        Assert.Equal("IOC123", result.Signals["B.indicator"]);
        Assert.Equal(42, result.Signals["A.size"]);
    }

    private static System.Net.IPEndPoint DummyEndPoint() => new(System.Net.IPAddress.Loopback, 8080);

    private sealed class StaticProcessResolver : IProcessContextResolver
    {
        public ProcessInfo Resolve(int processId) => new()
        {
            Pid = processId,
            Name = "AnalyzerTest",
            ExecutablePath = "C:/Temp/Analyzer.exe",
            DigitalSignature = "Unsigned",
            ParentPid = 1,
            IsSystemProcess = false
        };
    }

    private sealed class StubAnalyzer : IAnalyzer
    {
        private readonly string _name;
        private readonly bool _isSensitive;
        private readonly RiskLevel _riskLevel;
        private readonly string _reason;
        private readonly IReadOnlyDictionary<string, object?> _signals;

        public StubAnalyzer(string name, bool isSensitive, RiskLevel riskLevel, string reason, IReadOnlyDictionary<string, object?> signals)
        {
            _name = name;
            _isSensitive = isSensitive;
            _riskLevel = riskLevel;
            _reason = reason;
            _signals = signals;
        }

        public AnalyzerFinding Analyze(RawPacket packet, ProcessInfo process)
            => new(
                Analyzer: _name,
                IsSensitive: _isSensitive,
                Risk: _riskLevel,
                Reason: _reason,
                Signals: _signals,
                Process: process);
    }
}
