using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using AntiExfiltration.Monitoring;
using AntiExfiltration.Plugins;
using AntiExfiltration.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Text.Json;
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
    private readonly string _logDirectory;
    private readonly string _reportsDirectory;
    private readonly SystemLoadMonitor _loadMonitor;
    private readonly MonitoringHost _monitoringHost;
    private bool _isBusy;
    private string? _busyOperation;

    public ConsoleUi(SecureLogger logger, UiConfiguration configuration, UiContext context)
    {
        _logger = logger;
        _configuration = configuration;
        _context = context;
        _logDirectory = context.LogDirectory;
        _reportsDirectory = configuration.ReportsDirectory;
        _loadMonitor = context.LoadMonitor;
        _monitoringHost = context.MonitoringHost;
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
        var responses = new List<string>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return responses;
        }

        var parts = input.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        var command = parts[0].ToLowerInvariant();
        var argument = parts.Length > 1 ? parts[1].Trim() : null;

        if (_isBusy && command is not ("status" or "help" or "exit"))
        {
            responses.Add($"Operation '{_busyOperation}' is currently running. Please wait before executing '{command}'.");
            return responses;
        }

        switch (command)
        {
            case "switch":
            case "iface":
                responses.AddRange(SwitchInterface(argument));
                break;
            case "list":
            case "ifaces":
                responses.AddRange(ListInterfaces());
                break;
            case "integrity":
                _ = _context.IntegrityChecker.VerifyAsync(CancellationToken.None);
                responses.Add("Integrity verification scheduled.");
                break;
            case "refresh":
            case "menu":
            case "help":
                responses.Add("Dashboard refresh requested.");
                break;
            case "exit":
                responses.Add("Exiting application.");
                Environment.Exit(0);
                break;
            case "start":
            case "start-service":
                responses.AddRange(RunSynchronousOperation("Starting monitoring", () =>
                {
                    _monitoringHost.Start();
                    return new[] { "Monitoring host is running." };
                }));
                break;
            case "stop":
            case "stop-service":
                responses.AddRange(RunSynchronousOperation("Stopping monitoring", () =>
                {
                    _monitoringHost.StopAsync().GetAwaiter().GetResult();
                    return new[] { "Monitoring host stopped." };
                }));
                break;
            case "restart":
            case "restart-service":
                responses.AddRange(RunSynchronousOperation("Restarting monitoring", () =>
                {
                    _monitoringHost.RestartAsync().GetAwaiter().GetResult();
                    return new[] { "Monitoring host restarted." };
                }));
                break;
            case "export":
                responses.AddRange(RunSynchronousOperation("Exporting report", () =>
                {
                    var path = ReportExporter.ExportAsync(_reportsDirectory, _context, CancellationToken.None)
                        .GetAwaiter().GetResult();
                    return new[] { $"Report written to {path}." };
                }));
                break;
            case "decrypt":
            case "decrypt-load":
                responses.AddRange(DecodeAndSummarizeLoad(argument));
                break;
            case "load":
                responses.AddRange(SummarizeCurrentLoad());
                break;
            case "tree":
            case "process-tree":
                responses.AddRange(RenderProcessTree(argument));
                break;
            case "status":
                responses.Add($"Monitoring host status: {_monitoringHost.State}.");
                break;
            default:
                responses.Add("Unknown command. Available commands: start, stop, restart, switch <iface>, list, integrity, export, decrypt [path], load, tree [pid], status, help, exit.");
                break;
        }

        return responses;
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

    private IEnumerable<string> SwitchInterface(string? argument)
    {
        if (string.IsNullOrWhiteSpace(argument))
        {
            return new[] { "Usage: switch <interface name>." };
        }

        return _context.NetworkInterceptor.SwitchInterface(argument)
            ? new[] { $"Switched to interface '{argument}'." }
            : new[] { $"Interface '{argument}' was not found." };
    }

    private IEnumerable<string> ListInterfaces()
        => NetworkInterface.GetAllNetworkInterfaces()
            .Select(iface => $"Interface {iface.Name} ({iface.NetworkInterfaceType}, {iface.OperationalStatus}).")
            .ToList();


    private IEnumerable<string> RunSynchronousOperation(string description, Func<IEnumerable<string>> operation)
    {
        var responses = new List<string> { $"{description}..." };
        try
        {
            _isBusy = true;
            _busyOperation = description;
            responses.AddRange(operation());
            responses.Add($"{description} completed.");
        }
        catch (Exception ex)
        {
            responses.Add($"{description} failed: {ex.Message}");
        }
        finally
        {
            _busyOperation = null;
            _isBusy = false;
        }

        return responses;
    }

    private IEnumerable<string> DecodeAndSummarizeLoad(string? argument)
    {
        var logPath = argument;
        if (string.IsNullOrWhiteSpace(logPath))
        {
            if (!Directory.Exists(_logDirectory))
            {
                return new[] { "No logs directory found. Specify a path using 'decrypt <file>'." };
            }

            logPath = Directory.EnumerateFiles(_logDirectory, "log-*.bin", SearchOption.TopDirectoryOnly)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();
        }

        if (string.IsNullOrWhiteSpace(logPath) || !File.Exists(logPath))
        {
            return new[] { "No encrypted log file was found to decode." };
        }

        try
        {
            var samples = LogDecoder.DecodeRuntimeLoad(logPath);
            if (samples.Count == 0)
            {
                return new[] { $"Log {logPath} decoded successfully but no runtime load entries were found." };
            }

            var messages = new List<string>
            {
                $"Decoded {samples.Count} runtime load entries from {logPath}."
            };

            var latest = samples[^1];
            messages.Add(
                $"Latest recorded at {latest.Timestamp:yyyy-MM-dd HH:mm:ss}: CPU {latest.CpuPercent:F1}% | Working Set {latest.WorkingSetMb:F1} MB | Managed {latest.ManagedMemoryMb:F1} MB | Threads {latest.ThreadCount} | Handles {latest.HandleCount} | Network {FormatNetwork(latest.NetworkBytesPerSecond)}");

            var averageCpu = samples.Average(s => s.CpuPercent);
            var averageWorkingSet = samples.Average(s => s.WorkingSetMb);
            var averageManaged = samples.Average(s => s.ManagedMemoryMb);
            messages.Add($"Overall averages: CPU {averageCpu:F1}% | Working Set {averageWorkingSet:F1} MB | Managed {averageManaged:F1} MB.");

            return messages;
        }
        catch (Exception ex)
        {
            return new[] { $"Failed to decode runtime load: {ex.Message}" };
        }
    }

    private IEnumerable<string> SummarizeCurrentLoad()
    {
        var history = _loadMonitor.SnapshotHistory();
        if (history.Count == 0)
        {
            return new[] { "No runtime metrics captured yet." };
        }

        var latest = history[^1];
        var messages = new List<string>
        {
            $"Latest sample at {latest.Timestamp:HH:mm:ss}: CPU {latest.CpuPercent:F1}% | Working Set {latest.WorkingSetMb:F1} MB | Managed {latest.ManagedMemoryMb:F1} MB | Threads {latest.ThreadCount} | Handles {latest.HandleCount} | Network {FormatNetwork(latest.NetworkBytesPerSecond)}"
        };

        var take = Math.Min(10, history.Count);
        var recent = history.Skip(history.Count - take).ToList();
        messages.Add($"Average over last {recent.Count} samples: CPU {recent.Average(s => s.CpuPercent):F1}% | Working Set {recent.Average(s => s.WorkingSetMb):F1} MB | Managed {recent.Average(s => s.ManagedMemoryMb):F1} MB.");

        return messages;
    }

    private IEnumerable<string> RenderProcessTree(string? argument)
    {
        int? rootPid = null;
        if (!string.IsNullOrWhiteSpace(argument))
        {
            if (int.TryParse(argument, out var parsed))
            {
                rootPid = parsed;
            }
            else
            {
                return new[] { "Usage: tree [pid]." };
            }
        }

        var nodes = _context.ProcessMonitor.BuildProcessTree(rootPid);
        if (nodes.Count == 0)
        {
            return new[] { "No process information is currently available." };
        }

        var lines = new List<string>();
        for (var i = 0; i < nodes.Count; i++)
        {
            AppendTreeNode(lines, nodes[i], string.Empty, i == nodes.Count - 1, isRoot: true);
        }

        return lines;
    }

    private void AppendTreeNode(List<string> lines, ProcessMonitor.ProcessTreeNode node, string indent, bool isLast, bool isRoot = false)
    {
        var connector = isRoot ? string.Empty : indent + (isLast ? "└─" : "├─");
        var signedLabel = node.IsSigned ? "signed" : "unsigned";
        var executable = string.IsNullOrEmpty(node.ExecutablePath) ? "<unknown>" : Path.GetFileName(node.ExecutablePath);
        lines.Add($"{connector}[{node.ProcessId}] {node.Name} ({signedLabel}) {executable}");

        var childIndent = isRoot ? indent : indent + (isLast ? "  " : "│ ");
        for (var i = 0; i < node.Children.Count; i++)
        {
            AppendTreeNode(lines, node.Children[i], childIndent, i == node.Children.Count - 1);
        }
    }


    private static string FormatNetwork(double? bytesPerSecond)
    {
        if (bytesPerSecond is null)
        {
            return "n/a";
        }

        return $"{FormatBytes(bytesPerSecond.Value)}/s";
    }

    private static string FormatBytes(double value)
    {
        string[] units = { "B", "KB", "MB", "GB" };
        var size = value;
        var index = 0;
        while (size >= 1024 && index < units.Length - 1)
        {
            size /= 1024;
            index++;
        }

        return $"{size:F1} {units[index]}";
    }

    private void RenderDashboard()
    {
        Console.Clear();
        Console.WriteLine("=== AntiExfiltration Defender ===");
        Console.WriteLine($"Auto-refresh interval: {_configuration.RefreshInterval.TotalSeconds:0.#} seconds");
        Console.WriteLine("Submit commands using English keywords, for example 'switch Wi-Fi'.");
        Console.WriteLine();
        Console.WriteLine($"--- Snapshot {DateTimeOffset.Now:HH:mm:ss} ---");
        Console.WriteLine($"Monitoring state: {_monitoringHost.State}");
        if (_isBusy && !string.IsNullOrEmpty(_busyOperation))
        {
            Console.WriteLine($"In-progress operation: {_busyOperation}");
        }
        Console.WriteLine($"Active interface: {_context.NetworkInterceptor.ActiveInterface?.Name ?? "N/A"}");
        Console.WriteLine();

        RenderLoadSummary();
        RenderProcessSummary();
        RenderConnectionSummary();
        RenderHookSummary();
        RenderNotifications();
    }

    private void RenderLoadSummary()
    {
        Console.WriteLine("Runtime load (agent process):");
        var latest = _loadMonitor.Latest;
        if (latest is null)
        {
            Console.WriteLine("  No samples captured yet.");
            Console.WriteLine();
            return;
        }

        Console.WriteLine(
            $"  CPU {latest.CpuPercent:F1}% | Working Set {latest.WorkingSetMb:F1} MB | Managed {latest.ManagedMemoryMb:F1} MB | Threads {latest.ThreadCount} | Handles {latest.HandleCount} | Network {FormatNetwork(latest.NetworkBytesPerSecond)}");

        var history = _loadMonitor.SnapshotHistory();
        if (history.Count > 1)
        {
            var take = Math.Min(5, history.Count);
            var recent = history.Skip(history.Count - take).ToList();
            Console.WriteLine(
                $"  Avg last {recent.Count} samples: CPU {recent.Average(s => s.CpuPercent):F1}% | Working Set {recent.Average(s => s.WorkingSetMb):F1} MB | Managed {recent.Average(s => s.ManagedMemoryMb):F1} MB");
        }

        Console.WriteLine();
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
        Console.WriteLine("Commands: start | stop | restart | switch <iface> | list | integrity | export | decrypt [path] | load | tree [pid] | status | help | exit");
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
    public required MonitoringHost MonitoringHost { get; init; }
    public required SystemLoadMonitor LoadMonitor { get; init; }
    public required string LogDirectory { get; init; }
}

