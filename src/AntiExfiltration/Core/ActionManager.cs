using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;

namespace AntiExfiltration.Core;

public sealed class ActionManager
{
    private readonly SecureLogger _logger;
    private readonly BehaviorEngine _behaviorEngine;
    private readonly DefenseConfiguration _configuration;
    private readonly ConcurrentDictionary<int, DateTimeOffset> _networkBlocks = new();

    public ActionManager(SecureLogger logger, BehaviorEngine behaviorEngine, DefenseConfiguration configuration)
    {
        _logger = logger;
        _behaviorEngine = behaviorEngine;
        _configuration = configuration;
    }

    public void EvaluateAndRespond(int processId)
    {
        var score = _behaviorEngine.GetScore(processId);
        switch (score.Level)
        {
            case BehaviorEngine.BehaviorLevel.Normal:
                return;
            case BehaviorEngine.BehaviorLevel.Suspicious:
                LogDecision(processId, "monitor");
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
            foreach (ProcessThread thread in process.Threads)
            {
                var handle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (handle == IntPtr.Zero)
                {
                    continue;
                }

                NativeMethods.SuspendThread(handle);
                _ = Task.Delay(_configuration.ProcessSuspendDuration).ContinueWith(_ => NativeMethods.ResumeThread(handle));
            }

            LogDecision(processId, "suspend");
        }
        catch (Exception ex) when (ex is ArgumentException or Win32Exception)
        {
            LogDecision(processId, "suspendFailed", ex.Message);
        }
    }

    private void TerminateProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            process.Kill(entireProcessTree: true);
            LogDecision(processId, "terminate");
        }
        catch (Exception ex) when (ex is ArgumentException or Win32Exception)
        {
            LogDecision(processId, "terminateFailed", ex.Message);
        }
    }

    public void BlockNetwork(int processId)
    {
        _networkBlocks[processId] = DateTimeOffset.UtcNow.Add(_configuration.NetworkBlockDuration);
        LogDecision(processId, "networkBlocked");
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
    }
}
