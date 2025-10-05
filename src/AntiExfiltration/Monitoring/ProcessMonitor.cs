using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using AntiExfiltration.Plugins;
using AntiExfiltration.Security;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.Versioning;

namespace AntiExfiltration.Monitoring;

[SupportedOSPlatform("windows")]
public sealed class ProcessMonitor
{
    private readonly SecureLogger _logger;
    private readonly BehaviorEngine _behaviorEngine;
    private readonly ActionManager _actionManager;
    private readonly PluginManager _pluginManager;
    private readonly ProcessMonitoringConfiguration _configuration;
    private readonly ConcurrentDictionary<int, ProcessMetadata> _processes = new();
    private readonly HashSet<string> _allowListedNames;

    public ProcessMonitor(
        SecureLogger logger,
        BehaviorEngine behaviorEngine,
        ActionManager actionManager,
        PluginManager pluginManager,
        ProcessMonitoringConfiguration configuration)
    {
        _logger = logger;
        _behaviorEngine = behaviorEngine;
        _actionManager = actionManager;
        _pluginManager = pluginManager;
        _configuration = configuration;
        _allowListedNames = (configuration.AllowListedProcesses ?? Array.Empty<string>())
            .Select(p => Path.GetFileNameWithoutExtension(p).ToLowerInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public async Task RunAsync(CancellationToken token)
    {
        ManagementEventWatcher? creationWatcher = null;
        try
        {
            creationWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            creationWatcher.EventArrived += (_, args) =>
            {
                var pid = Convert.ToInt32(args.NewEvent.Properties["ProcessID"].Value);
                AnalyseProcess(pid);
            };
            creationWatcher.Start();
        }
        catch (ManagementException ex)
        {
            _logger.Log(new
            {
                timestamp = DateTimeOffset.UtcNow,
                eventType = "processWatcherDisabled",
                error = ex.Message
            });
        }

        try
        {
            while (!token.IsCancellationRequested)
            {
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        AnalyseProcess(process.Id);
                    }
                    finally
                    {
                        process.Dispose();
                    }
                }

                await Task.Delay(_configuration.ScanInterval, token).ConfigureAwait(false);
            }
        }
        finally
        {
            creationWatcher?.Stop();
            creationWatcher?.Dispose();
        }
    }

    private void AnalyseProcess(int processId)
    {
        if (processId <= 4)
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            var metadata = CaptureMetadata(process);
            _processes[processId] = metadata;
            EvaluateIndicators(metadata);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception)
        {
            // process terminated
            _processes.TryRemove(processId, out _);
            _logger.Log(new
            {
                timestamp = DateTimeOffset.UtcNow,
                eventType = "processRemoved",
                processId,
                message = ex.Message
            });
        }
    }

    private ProcessMetadata CaptureMetadata(Process process)
    {
        var filePath = SafeQuery(() => process.MainModule?.FileName) ?? string.Empty;
        var commandLine = QueryCommandLine(process.Id);
        var signed = SignatureVerifier.IsSigned(filePath);
        return new ProcessMetadata
        {
            ProcessId = process.Id,
            Name = process.ProcessName,
            CommandLine = commandLine,
            ExecutablePath = filePath,
            IsSigned = signed,
            ParentProcessId = ParentProcessUtilities.GetParentProcessId(process.Id)
        };
    }

    private void EvaluateIndicators(ProcessMetadata metadata)
    {
        if (IsAllowListed(metadata.Name))
        {
            return;
        }

        var indicators = new List<(string indicator, int weight)>();

        if (!metadata.IsSigned && metadata.ExecutiveDirectorySuspicious())
        {
            indicators.Add(("unsignedTempExecution", 2));
        }

        if (CommandLineAnalyzer.ContainsEncodedPowerShell(metadata.CommandLine))
        {
            indicators.Add(("powershellEncoded", 4));
        }

        if (CommandLineAnalyzer.ContainsMshta(metadata.CommandLine))
        {
            indicators.Add(("mshta", 4));
        }

        foreach (var plugin in _pluginManager.ActivePlugins)
        {
            foreach (var alert in plugin.AnalyzeProcess(metadata.ProcessId, metadata.Name, metadata.CommandLine, metadata.ExecutablePath))
            {
                indicators.Add((alert.Indicator, alert.Score));
            }
        }

        if (indicators.Count == 0)
        {
            return;
        }

        var score = _behaviorEngine.UpdateScore(metadata.ProcessId, existing =>
        {
            var updated = existing;
            foreach (var (indicator, weight) in indicators)
            {
                updated = updated.WithIndicator(indicator, weight, _behaviorEngine.Configuration);
            }

            return updated;
        });

        _actionManager.EvaluateAndRespond(metadata.ProcessId);

        _logger.Log(new
        {
            timestamp = DateTimeOffset.UtcNow,
            eventType = "processIndicators",
            metadata.ProcessId,
            metadata.Name,
            metadata.CommandLine,
            indicators = indicators.Select(i => new { i.indicator, i.weight }),
            score.Total,
            score.Level
        });
    }

    public IReadOnlyCollection<ProcessMetadata> SnapshotProcesses() => _processes.Values.ToList();

    public IReadOnlyList<ProcessTreeNode> BuildProcessTree(int? rootProcessId = null)
    {
        var snapshot = _processes.Values.ToList();
        if (snapshot.Count == 0)
        {
            return Array.Empty<ProcessTreeNode>();
        }

        var lookup = snapshot.ToLookup(p => p.ParentProcessId);
        var index = snapshot.ToDictionary(p => p.ProcessId);
        var visited = new HashSet<int>();

        IEnumerable<ProcessTreeNode> EnumerateChildren(ProcessMetadata metadata)
        {
            if (!visited.Add(metadata.ProcessId))
            {
                yield break;
            }

            foreach (var child in lookup[metadata.ProcessId]
                         .OrderBy(c => c.ProcessId))
            {
                yield return CreateNode(child);
            }

            visited.Remove(metadata.ProcessId);
        }

        ProcessTreeNode CreateNode(ProcessMetadata metadata)
        {
            var children = EnumerateChildren(metadata).ToList();
            return new ProcessTreeNode
            {
                ProcessId = metadata.ProcessId,
                ParentProcessId = metadata.ParentProcessId,
                Name = metadata.Name,
                ExecutablePath = metadata.ExecutablePath,
                CommandLine = metadata.CommandLine,
                IsSigned = metadata.IsSigned,
                Children = children
            };
        }

        List<ProcessTreeNode> roots;
        if (rootProcessId.HasValue && index.TryGetValue(rootProcessId.Value, out var rootMetadata))
        {
            roots = new List<ProcessTreeNode> { CreateNode(rootMetadata) };
        }
        else
        {
            roots = snapshot
                .Where(p => p.ParentProcessId <= 4 || !index.ContainsKey(p.ParentProcessId))
                .OrderBy(p => p.ProcessId)
                .Select(CreateNode)
                .ToList();
        }

        return roots;
    }

    private bool IsAllowListed(string processName)
        => _allowListedNames.Contains(processName);

    private static string QueryCommandLine(int processId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + processId);
            foreach (ManagementObject @object in searcher.Get())
            {
                return @object["CommandLine"]?.ToString() ?? string.Empty;
            }
        }
        catch
        {
            // ignore and fall back to empty command line
        }

        return string.Empty;
    }

    private static string? SafeQuery(Func<string?> query)
    {
        try
        {
            return query();
        }
        catch
        {
            return null;
        }
    }

    public sealed record ProcessMetadata
    {
        public int ProcessId { get; init; }
        public int ParentProcessId { get; init; }
        public string Name { get; init; } = string.Empty;
        public string ExecutablePath { get; init; } = string.Empty;
        public string CommandLine { get; init; } = string.Empty;
        public bool IsSigned { get; init; }
    }

    public sealed record ProcessTreeNode
    {
        public int ProcessId { get; init; }
        public int ParentProcessId { get; init; }
        public string Name { get; init; } = string.Empty;
        public string ExecutablePath { get; init; } = string.Empty;
        public string CommandLine { get; init; } = string.Empty;
        public bool IsSigned { get; init; }
        public IReadOnlyList<ProcessTreeNode> Children { get; init; } = Array.Empty<ProcessTreeNode>();
    }
}

internal static class ProcessMonitoringExtensions
{
    public static bool ExecutiveDirectorySuspicious(this ProcessMonitor.ProcessMetadata metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata.ExecutablePath))
        {
            return false;
        }

        var path = metadata.ExecutablePath.ToLowerInvariant();
        return path.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase)
               || path.Contains("\\appdata\\", StringComparison.OrdinalIgnoreCase)
               || path.Contains("\\downloads\\", StringComparison.OrdinalIgnoreCase);
    }
}
