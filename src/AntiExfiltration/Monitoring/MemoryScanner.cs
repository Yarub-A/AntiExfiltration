using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace AntiExfiltration.Monitoring;

[SupportedOSPlatform("windows")]
public sealed class MemoryScanner
{
    private readonly SecureLogger _logger;
    private readonly BehaviorEngine _behaviorEngine;
    private readonly ActionManager _actionManager;
    private readonly MemoryScanningConfiguration _configuration;
    private readonly ConcurrentDictionary<int, DateTimeOffset> _lastScan = new();

    public MemoryScanner(
        SecureLogger logger,
        BehaviorEngine behaviorEngine,
        ActionManager actionManager,
        MemoryScanningConfiguration configuration)
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
            var candidates = SelectProcessesForScan();

            foreach (var processId in candidates)
            {
                ScanProcess(processId);
            }

            await Task.Delay(_configuration.ScanInterval, token).ConfigureAwait(false);
        }
    }

    private IReadOnlyList<int> SelectProcessesForScan()
    {
        var candidates = new List<int>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                using (process)
                {
                    if (!ShouldInspect(process))
                    {
                        continue;
                    }

                    candidates.Add(process.Id);
                }
            }
            catch
            {
                // ignore inaccessible processes
            }
        }

        return candidates
            .OrderByDescending(pid => _behaviorEngine.GetScore(pid).Total)
            .ThenBy(pid => pid)
            .Take(_configuration.MaxConcurrentScans)
            .ToList();
    }

    private bool ShouldInspect(Process process)
    {
        if (process.HasExited)
        {
            return false;
        }

        if (process.Id <= 4)
        {
            return false;
        }

        if (_configuration.TargetProcesses.Contains(process.ProcessName + ".exe", StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        var score = _behaviorEngine.GetScore(process.Id);
        return score.Total >= _behaviorEngine.Configuration.SuspiciousThreshold;
    }

    private void ScanProcess(int processId)
    {
        using var process = GetProcessByIdSafe(processId);
        if (process is null)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (_lastScan.TryGetValue(process.Id, out var last) && now - last < _configuration.ScanInterval)
        {
            return;
        }

        _lastScan[process.Id] = now;

        try
        {
            var suspiciousRegions = new List<MemoryRegion>();
            using var handle = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryInformation | NativeMethods.ProcessAccessFlags.VirtualMemoryRead, false, process.Id);
            if (handle.IsInvalid)
            {
                return;
            }

            var address = IntPtr.Zero;
            var memInfo = new NativeMethods.MEMORY_BASIC_INFORMATION();
            while (NativeMethods.VirtualQueryEx(handle, address, out memInfo, (uint)Marshal.SizeOf(memInfo))
                   != IntPtr.Zero)
            {
                var protect = (NativeMethods.MemoryProtection)memInfo.Protect;
                if (protect.HasFlag(NativeMethods.MemoryProtection.PAGE_EXECUTE_READWRITE)
                    || protect.HasFlag(NativeMethods.MemoryProtection.PAGE_EXECUTE_WRITECOPY))
                {
                    suspiciousRegions.Add(new MemoryRegion
                    {
                        BaseAddress = memInfo.BaseAddress,
                        RegionSize = memInfo.RegionSize,
                        Protection = protect.ToString()
                    });
                }

                address = new IntPtr(memInfo.BaseAddress.ToInt64() + (long)memInfo.RegionSize);
            }

            if (suspiciousRegions.Count > 0)
            {
                var score = _behaviorEngine.UpdateScore(process.Id, existing =>
                    existing.WithIndicator("rwxMemory", 6, _behaviorEngine.Configuration));
                _actionManager.EvaluateAndRespond(process.Id);

                _logger.Log(new
                {
                    timestamp = DateTimeOffset.UtcNow,
                    eventType = "memoryAnomaly",
                    processId = process.Id,
                    processName = process.ProcessName,
                    suspiciousRegions
                });
            }
        }
        catch
        {
            // ignore processes that cannot be scanned
        }
    }

    private static Process? GetProcessByIdSafe(int processId)
    {
        try
        {
            return Process.GetProcessById(processId);
        }
        catch
        {
            return null;
        }
    }

    private sealed record MemoryRegion
    {
        public IntPtr BaseAddress { get; init; }
        public nuint RegionSize { get; init; }
        public string Protection { get; init; } = string.Empty;
    }

    private static class NativeMethods
    {
        [Flags]
        public enum MemoryProtection : uint
        {
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x0400,
            VirtualMemoryRead = 0x0010
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public nuint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualQueryEx(SafeProcessHandle hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(ProcessAccessFlags processAccess, bool inheritHandle, int processId);
    }
}
