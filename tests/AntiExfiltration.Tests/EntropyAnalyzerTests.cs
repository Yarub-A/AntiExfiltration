using System.Linq;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Context;
using AntiExfiltration.Core.Policy;
using Xunit;

namespace AntiExfiltration.Tests;

public class EntropyAnalyzerTests
{
    [Fact]
    public void Analyze_ReturnsHighRisk_ForHighEntropyPayload()
    {
        var analyzer = new EntropyAnalyzer(threshold: 7.0);
        var payload = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        var packet = new RawPacket(payload, DummyEndPoint(), DummyEndPoint(), ProtocolType.Tcp, 100, DateTimeOffset.UtcNow);
        var process = CreateProcessInfo(100);

        var finding = analyzer.Analyze(packet, process);

        Assert.True(finding.IsSensitive);
        Assert.Equal(Core.Common.RiskLevel.High, finding.Risk);

    private readonly IProcessContextResolver _resolver = new TestProcessResolver();

    [Fact]
    public void Analyze_ReturnsHighRisk_ForHighEntropyPayload()
    {
        var analyzer = new EntropyAnalyzer(_resolver, threshold: 7.0);
        var payload = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        var packet = new RawPacket(payload, DummyEndPoint(), DummyEndPoint(), ProtocolType.Tcp, 100, DateTimeOffset.UtcNow);

        var result = analyzer.Analyze(packet);

        Assert.True(result.IsSensitive);
        Assert.Equal(Core.Common.RiskLevel.High, result.Risk);
    }

    [Fact]
    public void Analyze_ReturnsBenign_ForLowEntropyPayload()
    {
        var analyzer = new EntropyAnalyzer(threshold: 7.0);
        var payload = System.Text.Encoding.UTF8.GetBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        var packet = new RawPacket(payload, DummyEndPoint(), DummyEndPoint(), ProtocolType.Tcp, 101, DateTimeOffset.UtcNow);
        var process = CreateProcessInfo(101);

        var finding = analyzer.Analyze(packet, process);

        Assert.False(finding.IsSensitive);
        Assert.Equal(Core.Common.RiskLevel.Low, finding.Risk);

        var analyzer = new EntropyAnalyzer(_resolver, threshold: 7.0);
        var payload = System.Text.Encoding.UTF8.GetBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        var packet = new RawPacket(payload, DummyEndPoint(), DummyEndPoint(), ProtocolType.Tcp, 101, DateTimeOffset.UtcNow);

        var result = analyzer.Analyze(packet);

        Assert.False(result.IsSensitive);
        Assert.Equal(Core.Common.RiskLevel.Low, result.Risk);
    }

    private static System.Net.IPEndPoint DummyEndPoint() => new(System.Net.IPAddress.Loopback, 12345);

    private static ProcessInfo CreateProcessInfo(int processId) => new()
    {
        Pid = processId,
        Name = "UnitTest",
        ExecutablePath = "C:/Tests/UnitTest.exe",
        DigitalSignature = "Unsigned",
        ParentPid = 1,
        IsSystemProcess = false
    };

    private sealed class TestProcessResolver : IProcessContextResolver
    {
        public ProcessInfo Resolve(int processId) => new()
        {
            Pid = processId,
            Name = "UnitTest",
            ExecutablePath = "C:/Tests/UnitTest.exe",
            DigitalSignature = "Unsigned",
            ParentPid = 1,
            IsSystemProcess = false
        };
    }
 
}
