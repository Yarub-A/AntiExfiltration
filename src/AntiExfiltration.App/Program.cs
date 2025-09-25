using AntiExfiltration.Core.Action;
using AntiExfiltration.Core.Capture;
using AntiExfiltration.Core.Context;
using AntiExfiltration.Core.Decisions;
=======
using AntiExfiltration.Core.Decision;
using AntiExfiltration.Core.Intel;
using AntiExfiltration.Core.Logging;
using AntiExfiltration.Core.Policy;
using AntiExfiltration.Core.Pipeline;

// NOTE: This console host wires the modular components using in-memory implementations.
// Actual production integrations should replace the placeholders with platform-specific drivers.

var threatIntel = new ThreatIntelManager();
threatIntel.LoadDestinations(new[] { "203.0.113.50", "198.51.100.22" });
threatIntel.LoadKeywords(new[] { "leak", "exfil", "secret" });

ICaptureProvider captureProvider = new InMemoryCaptureProvider();
IProcessContextResolver processResolver = new InMemoryProcessContextResolver();
var analyzers = new IAnalyzer[]
{
    new SignatureAnalyzer(threatIntel),
    new EntropyAnalyzer()
=======
    new SignatureAnalyzer(threatIntel, processResolver),
    new EntropyAnalyzer(processResolver)
};
var policyEngine = new PolicyEngine(analyzers, processResolver);
var decisionEngine = new DecisionEngine(new DecisionEngineOptions());
IEventLogger logger = new JsonEventLogger(Path.Combine(AppContext.BaseDirectory, "events.log"));
var packetDropper = new NullPacketDropper();
var dataObfuscator = new NullDataObfuscator();
var processTerminator = new NullProcessTerminator(logger);
IEnforcementAction actionExecutor = new ActionExecutor(packetDropper, dataObfuscator, processTerminator, logger);

var pipeline = new AntiExfiltrationPipeline(captureProvider, policyEngine, decisionEngine, actionExecutor);
pipeline.Start();

Console.WriteLine("Anti-Exfiltration pipeline started. Press Ctrl+C to exit.");
await Task.Delay(Timeout.InfiniteTimeSpan);

// Below are placeholder implementations for demonstration and unit testing.

file sealed class InMemoryCaptureProvider : ICaptureProvider
{
    public event EventHandler<AntiExfiltration.Core.Capture.RawPacket>? PacketCaptured;

    public void Start()
    {
        Task.Run(async () =>
        {
            var rnd = new Random();
            while (true)
            {
                await Task.Delay(TimeSpan.FromSeconds(5));
                var payload = System.Text.Encoding.UTF8.GetBytes(rnd.Next(0, 2) == 0 ? "user=password" : "harmless ping");
                var packet = new AntiExfiltration.Core.Capture.RawPacket(
                    payload,
                    new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 5000),
                    new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.50"), 443),
                    AntiExfiltration.Core.Capture.ProtocolType.Https,
                    processId: 1234,
                    Timestamp: DateTimeOffset.UtcNow);
                PacketCaptured?.Invoke(this, packet);
            }
        });
    }
}

file sealed class InMemoryProcessContextResolver : IProcessContextResolver
{
    public AntiExfiltration.Core.Context.ProcessInfo Resolve(int processId) => new()
    {
        Pid = processId,
        Name = "TestProcess",
        ExecutablePath = "C:/Temp/TestProcess.exe",
        DigitalSignature = "Unsigned",
        ParentPid = 1,
        IsSystemProcess = false
    };
}

file sealed class NullPacketDropper : IPacketDropper
{
    public void Drop(AntiExfiltration.Core.Capture.RawPacket packet)
    {
        Console.WriteLine($"[DROP] Packet to {packet.Destination} blocked.");
    }
}

file sealed class NullDataObfuscator : IDataObfuscator
{
    public void Obfuscate(AntiExfiltration.Core.Capture.RawPacket packet)
    {
        Console.WriteLine($"[OBFUSCATE] Payload of size {packet.Payload.Length} bytes obfuscated.");
    }
}

file sealed class NullProcessTerminator : IProcessTerminator
{
    private readonly IEventLogger _logger;

    public NullProcessTerminator(IEventLogger logger)
    {
        _logger = logger;
    }

    public void Terminate(AntiExfiltration.Core.Context.ProcessInfo processInfo)
    {
        _logger.LogAlert(new AntiExfiltration.Core.Capture.RawPacket(Array.Empty<byte>(), new System.Net.IPEndPoint(System.Net.IPAddress.None, 0), new System.Net.IPEndPoint(System.Net.IPAddress.None, 0), AntiExfiltration.Core.Capture.ProtocolType.Unknown, processInfo.Pid, DateTimeOffset.UtcNow), processInfo);
    }
}
