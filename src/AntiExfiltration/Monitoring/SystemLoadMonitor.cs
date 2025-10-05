using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace AntiExfiltration.Monitoring;

[SupportedOSPlatform("windows")]
public sealed class SystemLoadMonitor
{
    private readonly SecureLogger _logger;
    private readonly LoadMonitoringConfiguration _configuration;
    private readonly Func<NetworkInterface?> _activeInterfaceProvider;
    private readonly ConcurrentQueue<LoadSample> _history = new();
    private readonly object _networkLock = new();

    private TimeSpan _lastCpuTime;
    private DateTimeOffset _lastCpuSample;
    private long _lastBytesSent;
    private long _lastBytesReceived;
    private DateTimeOffset _lastNetworkSample;

    public SystemLoadMonitor(
        SecureLogger logger,
        LoadMonitoringConfiguration configuration,
        Func<NetworkInterface?> activeInterfaceProvider)
    {
        _logger = logger;
        _configuration = configuration;
        _activeInterfaceProvider = activeInterfaceProvider;
    }

    public LoadSample? Latest => _history.LastOrDefault();

    public IReadOnlyList<LoadSample> SnapshotHistory() => _history.ToList();

    public async Task RunAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            var sample = CaptureSample();
            if (sample is not null)
            {
                _history.Enqueue(sample);
                TrimHistory();
                _logger.Log(new
                {
                    timestamp = sample.Timestamp,
                    eventType = "runtimeLoad",
                    cpuPercent = Math.Round(sample.CpuPercent, 2),
                    workingSetMb = Math.Round(sample.WorkingSetMb, 2),
                    managedMemoryMb = Math.Round(sample.ManagedMemoryMb, 2),
                    threadCount = sample.ThreadCount,
                    handleCount = sample.HandleCount,
                    networkBytesPerSecond = sample.NetworkBytesPerSecond
                });
            }

            try
            {
                await Task.Delay(_configuration.SampleInterval, token).ConfigureAwait(false);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    private LoadSample? CaptureSample()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            var now = DateTimeOffset.UtcNow;
            var totalCpu = process.TotalProcessorTime;

            double cpuPercent = 0;
            if (_lastCpuSample != default)
            {
                var cpuDelta = totalCpu - _lastCpuTime;
                var timeDelta = now - _lastCpuSample;
                if (timeDelta > TimeSpan.Zero)
                {
                    cpuPercent = Math.Clamp(
                        cpuDelta.TotalMilliseconds / (Environment.ProcessorCount * timeDelta.TotalMilliseconds) * 100,
                        0,
                        100 * Environment.ProcessorCount);
                }
            }

            _lastCpuTime = totalCpu;
            _lastCpuSample = now;

            double? networkThroughput = TryCaptureNetworkThroughput(now);

            var workingSetMb = process.WorkingSet64 / 1024d / 1024d;
            var managedMemoryMb = GC.GetTotalMemory(forceFullCollection: false) / 1024d / 1024d;

            var sample = new LoadSample
            {
                Timestamp = now,
                CpuPercent = cpuPercent,
                WorkingSetMb = workingSetMb,
                ManagedMemoryMb = managedMemoryMb,
                ThreadCount = process.Threads.Count,
                HandleCount = process.HandleCount,
                NetworkBytesPerSecond = networkThroughput
            };

            return sample;
        }
        catch
        {
            return null;
        }
    }

    private double? TryCaptureNetworkThroughput(DateTimeOffset now)
    {
        try
        {
            var networkInterface = _activeInterfaceProvider?.Invoke();
            if (networkInterface is null)
            {
                return null;
            }

            lock (_networkLock)
            {
                var stats = networkInterface.GetIPStatistics();
                var sent = stats.BytesSent;
                var received = stats.BytesReceived;
                if (_lastNetworkSample == default)
                {
                    _lastNetworkSample = now;
                    _lastBytesSent = sent;
                    _lastBytesReceived = received;
                    return null;
                }

                var deltaTime = (now - _lastNetworkSample).TotalSeconds;
                if (deltaTime <= 0)
                {
                    return null;
                }

                var delta = (sent - _lastBytesSent) + (received - _lastBytesReceived);
                _lastNetworkSample = now;
                _lastBytesSent = sent;
                _lastBytesReceived = received;
                return Math.Max(0, delta / deltaTime);
            }
        }
        catch
        {
            return null;
        }
    }

    private void TrimHistory()
    {
        while (_history.Count > _configuration.HistorySize)
        {
            _history.TryDequeue(out _);
        }
    }
}
