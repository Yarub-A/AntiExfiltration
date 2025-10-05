using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;

namespace AntiExfiltration.Monitoring;

[SupportedOSPlatform("windows")]
public sealed class ApiHookManager
{
    private readonly SecureLogger _logger;
    private readonly BehaviorEngine _behaviorEngine;
    private readonly ActionManager _actionManager;
    private readonly ApiHookConfiguration _configuration;
    private readonly ConcurrentDictionary<int, HookState> _hookedProcesses = new();

    public ApiHookManager(
        SecureLogger logger,
        BehaviorEngine behaviorEngine,
        ActionManager actionManager,
        ApiHookConfiguration configuration)
    {
        _logger = logger;
        _behaviorEngine = behaviorEngine;
        _actionManager = actionManager;
        _configuration = configuration;
    }

    public async Task RunAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            var observed = new HashSet<int>();

            foreach (var target in _configuration.TargetProcesses)
            {
                var processName = Path.GetFileNameWithoutExtension(target);
                if (string.IsNullOrWhiteSpace(processName))
                {
                    continue;
                }

                foreach (var process in Process.GetProcessesByName(processName))
                {
                    using (process)
                    {
                        observed.Add(process.Id);

                        if (_hookedProcesses.ContainsKey(process.Id))
                        {
                            continue;
                        }

                        if (!ProcessHooker.TryHook(process, out var hookState))
                        {
                            continue;
                        }

                        _hookedProcesses[process.Id] = hookState;
                        _logger.Log(new
                        {
                            timestamp = DateTimeOffset.UtcNow,
                            eventType = "apiHooked",
                            processId = process.Id,
                            processName = process.ProcessName,
                            hookState.Modules
                        });
                    }
                }
            }

            foreach (var pid in _hookedProcesses.Keys.ToArray())
            {
                if (!observed.Contains(pid))
                {
                    _hookedProcesses.TryRemove(pid, out _);
                }
            }

            await Task.Delay(TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
        }
    }

    public IReadOnlyDictionary<int, HookState> HookedProcesses => _hookedProcesses;
}

public sealed record HookState(int ProcessId, IReadOnlyList<string> Modules);

internal static class ProcessHooker
{
    public static bool TryHook(Process process, out HookState hookState)
    {
        try
        {
            var modules = process.Modules.Cast<ProcessModule>().Select(m => m.ModuleName).ToList();
            hookState = new HookState(process.Id, modules);
            return true;
        }
        catch
        {
            hookState = new HookState(process.Id, Array.Empty<string>());
            return false;
        }
    }
}
