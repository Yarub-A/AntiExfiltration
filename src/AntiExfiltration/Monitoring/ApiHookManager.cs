using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.Diagnostics;
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
            foreach (var process in Process.GetProcesses())
            {
                if (!_configuration.TargetProcesses.Contains(process.ProcessName + ".exe", StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

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
