using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using AntiExfiltration.Monitoring;
using AntiExfiltration.Plugins;
using AntiExfiltration.Security;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace AntiExfiltration.UI;

[SupportedOSPlatform("windows")]
public sealed class ConsoleUi
{
    private readonly SecureLogger _logger;
    private readonly UiConfiguration _configuration;
    private readonly UiContext _context;

    public ConsoleUi(SecureLogger logger, UiConfiguration configuration, UiContext context)
    {
        _logger = logger;
        _configuration = configuration;
        _context = context;
    }

    public Task RunAsync(CancellationToken token)
        => Task.Run(() => RunLoop(token), token);

    private void RunLoop(CancellationToken token)
    {
        Console.WriteLine("=== AntiExfiltration Defender ===");
        Console.WriteLine("Type 'help' to list commands. Press Enter to refresh the dashboard.");
        Console.WriteLine($"Configured snapshot interval: {_configuration.RefreshInterval.TotalSeconds:0.#}s");

        while (!token.IsCancellationRequested)
        {
            RenderDashboard();
            PrintMenu();

            Console.Write("> ");
            var input = Console.ReadLine();
            if (input is null)
            {
                break;
            }

            input = input.Trim();

            if (token.IsCancellationRequested)
            {
                break;
            }

            if (string.IsNullOrEmpty(input))
            {
                continue;
            }

            HandleCommand(input);
        }
    }

    private void HandleCommand(string input)
    {
        _logger.Log(new
        {
            timestamp = DateTimeOffset.UtcNow,
            eventType = "uiCommand",
            command = input
        });

        switch (input.ToLowerInvariant())
        {
            case "1":
            case "switch":
                Console.Write("Interface name: ");
                var name = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(name))
                {
                    Console.WriteLine("No interface name was provided.");
                    break;
                }

                if (_context.NetworkInterceptor.SwitchInterface(name.Trim()))
                {
                    Console.WriteLine($"Switched to interface '{name.Trim()}'.");
                }
                else
                {
                    Console.WriteLine($"Interface '{name.Trim()}' was not found.");
                }

                break;
            case "2":
            case "list":
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    Console.WriteLine($"- {iface.Name} ({iface.NetworkInterfaceType}, {iface.OperationalStatus})");
                }

                break;
            case "3":
            case "integrity":
                _ = _context.IntegrityChecker.VerifyAsync(CancellationToken.None);
                Console.WriteLine("Integrity verification scheduled.");
                break;
            case "4":
            case "refresh":
            case "help":
                // Refresh handled by the next loop iteration.
                break;
            case "5":
            case "exit":
                Environment.Exit(0);
                break;
            default:
                Console.WriteLine("Unknown command. Type 'help' to list available options.");
                break;
        }
    }

    private void RenderDashboard()
    {
        Console.WriteLine();
        Console.WriteLine($"--- Snapshot {DateTimeOffset.Now:HH:mm:ss} ---");
        Console.WriteLine($"Active interface: {_context.NetworkInterceptor.ActiveInterface?.Name ?? "N/A"}");
        Console.WriteLine();

        RenderProcessSummary();
        RenderConnectionSummary();
        RenderHookSummary();
    }

    private void RenderProcessSummary()
    {
        Console.WriteLine("Top processes by risk score:");
        var processes = _context.ProcessMonitor.SnapshotProcesses();
        var ranked = processes
            .Select(p => (Process: p, Score: _context.BehaviorEngine.GetScore(p.ProcessId)))
            .OrderByDescending(tuple => tuple.Score.Total)
            .ThenBy(tuple => tuple.Process.ProcessId)
            .Take(10)
            .ToList();

        if (ranked.Count == 0)
        {
            Console.WriteLine("  No process telemetry has been captured yet.");
            Console.WriteLine();
            return;
        }

        foreach (var entry in ranked)
        {
            Console.WriteLine(
                $"  PID {entry.Process.ProcessId,-6} {entry.Process.Name,-20} Score {entry.Score.Total,3} Level {entry.Score.Level}");
        }

        Console.WriteLine();
    }

    private void RenderConnectionSummary()
    {
        Console.WriteLine("Recent outbound connections:");
        var connections = _context.NetworkInterceptor.SnapshotConnections();
        if (connections.Count == 0)
        {
            Console.WriteLine("  No outbound activity observed.");
            Console.WriteLine();
            return;
        }

        foreach (var connection in connections.Take(10))
        {
            var payload = string.IsNullOrEmpty(connection.PayloadSnapshot)
                ? "No indicators"
                : connection.PayloadSnapshot;

            Console.WriteLine(
                $"  PID {connection.ProcessId,-6} {connection.LocalAddress}:{connection.LocalPort} -> {connection.RemoteAddress}:{connection.RemotePort} | {payload} | Last {connection.LastObserved:HH:mm:ss}");
        }

        Console.WriteLine();
    }

    private void RenderHookSummary()
    {
        Console.WriteLine("Monitored API hook targets:");
        if (_context.ApiHookManager.HookedProcesses.Count == 0)
        {
            Console.WriteLine("  No processes have been instrumented yet.");
            Console.WriteLine();
            return;
        }

        foreach (var hook in _context.ApiHookManager.HookedProcesses.Values)
        {
            var modules = hook.Modules.Take(5);
            Console.WriteLine($"  PID {hook.ProcessId,-6} Modules: {string.Join(", ", modules)}");
        }

        Console.WriteLine();
    }

    private void PrintMenu()
    {
        Console.WriteLine("Commands: [1] switch  [2] list  [3] integrity  [4] refresh  [5] exit");
    }
}

public sealed class UiContext
{
    public required NetworkInterceptor NetworkInterceptor { get; init; }
    public required ProcessMonitor ProcessMonitor { get; init; }
    public required MemoryScanner MemoryScanner { get; init; }
    public required ApiHookManager ApiHookManager { get; init; }
    public required PluginManager PluginManager { get; init; }
    public required BehaviorEngine BehaviorEngine { get; init; }
    public required ActionManager ActionManager { get; init; }
    public required CertificateManager CertificateManager { get; init; }
    public required IntegrityChecker IntegrityChecker { get; init; }
}
