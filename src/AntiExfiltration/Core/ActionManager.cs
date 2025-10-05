using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace AntiExfiltration.Core;

public sealed class ActionManager
{
    private readonly SecureLogger _logger;
    private readonly BehaviorEngine _behaviorEngine;
    private readonly DefenseConfiguration _configuration;
    private readonly ConcurrentDictionary<int, DateTimeOffset> _networkBlocks = new();
    private readonly ConcurrentDictionary<int, DateTimeOffset> _actionCooldowns = new();
    private readonly ConcurrentDictionary<int, DateTimeOffset> _terminateBackoff = new();
    private readonly SemaphoreSlim _terminateSemaphore;

    public ActionManager(SecureLogger logger, BehaviorEngine behaviorEngine, DefenseConfiguration configuration)
    {
        _logger = logger;
        _behaviorEngine = behaviorEngine;
        _configuration = configuration;
        var maxTerminates = Math.Max(1, configuration.MaxConcurrentTerminates);
        _terminateSemaphore = new SemaphoreSlim(maxTerminates, maxTerminates);
    }

    public void EvaluateAndRespond(int processId)
    {
        if (!CanTarget(processId))
        {
            return;
        }

        var score = _behaviorEngine.GetScore(processId);
        if (score.Level == BehaviorEngine.BehaviorLevel.Normal)
        {
            return;
        }

        if (IsOnCooldown(processId))
        {
            return;
        }

        switch (score.Level)
        {
            case BehaviorEngine.BehaviorLevel.Normal:
                return;
            case BehaviorEngine.BehaviorLevel.Suspicious:
                LogDecision(processId, "monitor");
                ApplyCooldown(processId);
                break;
            case BehaviorEngine.BehaviorLevel.Malicious:
                SuspendProcess(processId);
                break;
            case BehaviorEngine.BehaviorLevel.Critical:
                TerminateProcess(processId);
                break;
        }
    }

    private void SuspendProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            if (!CanTarget(process.Id) || process.HasExited)
            {
                return;
            }

            foreach (ProcessThread thread in process.Threads)
            {
                var handle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (handle == IntPtr.Zero)
                {
                    continue;
                }

                var previousCount = NativeMethods.SuspendThread(handle);
                if (previousCount == uint.MaxValue)
                {
                    NativeMethods.CloseHandle(handle);
                    continue;
                }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(_configuration.ProcessSuspendDuration).ConfigureAwait(false);
                        NativeMethods.ResumeThread(handle);
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(handle);
                    }
                });
            }

            LogDecision(processId, "suspend");
            ApplyCooldown(processId);
        }
        catch (Exception ex) when (ex is ArgumentException or Win32Exception)
        {
            LogDecision(processId, "suspendFailed", ex.Message);
            ApplyCooldown(processId);
        }
    }

    private void TerminateProcess(int processId)
    {
        if (_configuration.MaxConcurrentTerminates <= 0)
        {
            LogDecision(processId, "terminateSkipped", "Termination disabled by configuration.");
            ApplyCooldown(processId);
            return;
        }

        if (_terminateBackoff.TryGetValue(processId, out var retryAfter) && retryAfter > DateTimeOffset.UtcNow)
        {
            LogDecision(processId, "terminateDeferred", $"Retry after {retryAfter:O}");
            ApplyCooldown(processId);
            return;
        }

        if (!_terminateSemaphore.Wait(0))
        {
            LogDecision(processId, "terminateDeferred", "Concurrency limit reached.");
            ApplyCooldown(processId);
            return;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            if (!CanTarget(process.Id) || process.HasExited)
            {
                LogDecision(processId, "terminateSkipped", "Process already exited or protected.");
                return;
            }

            process.Kill(entireProcessTree: true);
            _terminateBackoff.TryRemove(processId, out _);
            LogDecision(processId, "terminate");
        }
        catch (Exception ex) when (ex is ArgumentException or Win32Exception or InvalidOperationException)
        {
            _terminateBackoff[processId] = DateTimeOffset.UtcNow + _configuration.TerminateFailureBackoff;
            LogDecision(processId, "terminateFailed", ex.Message);
        }
        finally
        {
            _terminateSemaphore.Release();
            ApplyCooldown(processId);
        }
    }

    public void BlockNetwork(int processId)
    {
        if (!CanTarget(processId))
        {
            return;
        }

        _networkBlocks[processId] = DateTimeOffset.UtcNow.Add(_configuration.NetworkBlockDuration);
        LogDecision(processId, "networkBlocked");
        ApplyCooldown(processId);
    }

    public bool IsNetworkBlocked(int processId)
    {
        if (_networkBlocks.TryGetValue(processId, out var until))
        {
            if (until > DateTimeOffset.UtcNow)
            {
                return true;
            }

            _networkBlocks.TryRemove(processId, out _);
        }

        return false;
    }

    private void LogDecision(int processId, string decision, string? error = null)
    {
        _logger.Log(new
        {
            timestamp = DateTimeOffset.UtcNow,
            eventType = "defenseAction",
            processId,
            decision,
            error
        });
    }

    private bool CanTarget(int processId)
        => processId > 4 && processId != Environment.ProcessId;

    private bool IsOnCooldown(int processId)
    {
        if (_configuration.ActionCooldown <= TimeSpan.Zero)
        {
            return false;
        }

        if (_actionCooldowns.TryGetValue(processId, out var until))
        {
            if (until > DateTimeOffset.UtcNow)
            {
                return true;
            }

            _actionCooldowns.TryRemove(processId, out _);
        }

        return false;
    }

    private void ApplyCooldown(int processId)
    {
        if (_configuration.ActionCooldown <= TimeSpan.Zero)
        {
            return;
        }

        _actionCooldowns[processId] = DateTimeOffset.UtcNow + _configuration.ActionCooldown;
    }

    private static class NativeMethods
    {
        [Flags]
        public enum ThreadAccess : uint
        {
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ResumeThread(IntPtr hThread);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
