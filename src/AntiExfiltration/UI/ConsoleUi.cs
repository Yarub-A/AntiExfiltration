using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using AntiExfiltration.Monitoring;
using AntiExfiltration.Plugins;
using AntiExfiltration.Security;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace AntiExfiltration.UI;

[SupportedOSPlatform("windows")]
public sealed class ConsoleUi
{
    private readonly SecureLogger _logger;
    private readonly UiConfiguration _configuration;
    private readonly UiContext _context;
    private readonly LinkedList<string> _notifications = new();
    private readonly object _notificationLock = new();

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
        var nextRefresh = DateTimeOffset.MinValue;

        while (!token.IsCancellationRequested)
        {
            if (DateTimeOffset.UtcNow >= nextRefresh)
            {
                RenderDashboard();
                PrintMenu();
                Console.Write("> ");
                nextRefresh = DateTimeOffset.UtcNow + _configuration.RefreshInterval;
            }

            if (Console.KeyAvailable)
            {
                var input = Console.ReadLine();
                if (input is null)
                {
                    break;
                }

                input = input.Trim();
                if (!string.IsNullOrEmpty(input))
                {
                    HandleCommand(input);
                }

                nextRefresh = DateTimeOffset.MinValue;
            }
            else
            {
                Thread.Sleep(100);
            }
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

        var responses = ExecuteCommand(input);
        foreach (var message in responses)
        {
            AddNotification(message);
        }
    }

    private IEnumerable<string> ExecuteCommand(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            yield break;
        }

        var parts = input.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        var command = parts[0].ToLowerInvariant();
        var argument = parts.Length > 1 ? parts[1].Trim() : null;

        switch (command)
        {
            case "1":
            case "switch":
                if (string.IsNullOrWhiteSpace(argument))
                {
                    yield return "Usage: switch <interface name>.";
                    yield break;
                }

                if (_context.NetworkInterceptor.SwitchInterface(argument))
                {
                    yield return $"Switched to interface '{argument}'.";
                }
                else
                {
                    yield return $"Interface '{argument}' was not found.";
                }

                break;
            case "2":
            case "list":
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    yield return $"Interface {iface.Name} ({iface.NetworkInterfaceType}, {iface.OperationalStatus}).";
                }

                break;
            case "3":
            case "integrity":
                _ = _context.IntegrityChecker.VerifyAsync(CancellationToken.None);
                yield return "Integrity verification scheduled.";
                break;
            case "4":
            case "refresh":
            case "help":
                yield return "Dashboard refresh requested.";
                break;
            case "5":
            case "exit":
                yield return "Exiting application.";
                Environment.Exit(0);
                break;
            default:
                yield return "Unknown command. Use: switch <name>, list, integrity, refresh, help, or exit.";
                break;
        }
    }

    private void AddNotification(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        lock (_notificationLock)
        {
            _notifications.AddFirst($"{DateTimeOffset.Now:HH:mm:ss} {message}");
            while (_notifications.Count > 6)
            {
                _notifications.RemoveLast();
            }
        }
    }

    private void RenderDashboard()
    {
        Console.Clear();
        Console.WriteLine("=== AntiExfiltration Defender ===");
        Console.WriteLine($"Auto-refresh interval: {_configuration.RefreshInterval.TotalSeconds:0.#} seconds");
        Console.WriteLine("Submit commands using English keywords, for example 'switch Wi-Fi'.");
        Console.WriteLine();
        Console.WriteLine($"--- Snapshot {DateTimeOffset.Now:HH:mm:ss} ---");
        Console.WriteLine($"Active interface: {_context.NetworkInterceptor.ActiveInterface?.Name ?? "N/A"}");
        Console.WriteLine();

        RenderProcessSummary();
        RenderConnectionSummary();
        RenderHookSummary();
        RenderNotifications();
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

    private void RenderNotifications()
    {
        Console.WriteLine("Recent commands:");
        List<string> snapshot;
        lock (_notificationLock)
        {
            snapshot = _notifications.ToList();
        }

        if (snapshot.Count == 0)
        {
            Console.WriteLine("  No commands executed yet.");
        }
        else
        {
            foreach (var note in snapshot)
            {
                Console.WriteLine($"  {note}");
            }
        }

        Console.WriteLine();
    }

    private void PrintMenu()
    {
        Console.WriteLine("Commands: switch <name> | list | integrity | refresh | help | exit");
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
