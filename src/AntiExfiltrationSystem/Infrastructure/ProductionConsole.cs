using AntiExfiltrationSystem.Core;
using AntiExfiltrationSystem.Detection;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.Infrastructure;

public sealed class ProductionConsole
{
    private readonly ProductionDetectionEngine _engine;
    private readonly ConsoleTable _table;

    public ProductionConsole()
    {
        _engine = new ProductionDetectionEngine();
        _table = new ConsoleTable("Metric", "Current Value");
    }

    public async Task StartAsync()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.Title = "Anti-Exfiltration Shield";
        RenderHeader();
        await _engine.StartAsync();
        await RenderLoopAsync();
    }

    private async Task RenderLoopAsync()
    {
        while (true)
        {
            var snapshot = _engine.GetStatistics();
            Console.Clear();
            RenderHeader();
            _table.Clear();
            _table.AddRow("Packets inspected", snapshot.PacketsInspected.ToString("N0"))
                .AddRow("Connections blocked", snapshot.BlockedConnections.ToString("N0"))
                .AddRow("Processes tracked", snapshot.ProcessesTracked.ToString("N0"))
                .AddRow("Memory scans", snapshot.MemoryScans.ToString("N0"))
                .AddRow("Confirmed threats", snapshot.ConfirmedThreats.ToString("N0"));
            _table.Write();
            RenderDetections(snapshot.RecentDetections);
            await Task.Delay(TimeSpan.FromSeconds(1));
        }
    }

    private static void RenderHeader()
    {
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine("🛡️  Anti-Exfiltration Shield - Live Mode");
        Console.WriteLine($"⏱️  {DateTime.Now:yyyy/MM/dd HH:mm:ss}");
        Console.WriteLine("═══════════════════════════════════════════════════════════\n");
    }

    private static void RenderDetections(IReadOnlyList<DetectionEvent> events)
    {
        if (events.Count == 0)
        {
            Console.WriteLine("No alerts at this time.");
            return;
        }

        Console.WriteLine("🚨 Recent threat log:");
        foreach (var detection in events.OrderByDescending(d => d.Timestamp).Take(10))
        {
            Console.WriteLine($"[{detection.Timestamp:HH:mm:ss}] {detection.ProcessName} → {detection.RemoteEndpoint} :: {detection.ThreatLabel} ({detection.ActionTaken})");
        }
    }
}
