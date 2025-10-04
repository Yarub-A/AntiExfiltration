using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Management;
using AntiExfiltrationSystem.Detection;
using AntiExfiltrationSystem.Memory;
using AntiExfiltrationSystem.Networking;
using AntiExfiltrationSystem.ProcessMonitoring;
using AntiExfiltrationSystem.ReverseProxy;
using AntiExfiltrationSystem.Utilities;

namespace AntiExfiltrationSystem.Core;

public sealed class ProductionDetectionEngine : IAsyncDisposable
{
    private readonly List<INetworkMonitor> _monitors = new();
    private readonly ProductionReverseProxy _reverseProxy = new();
    private readonly ProcessTracker _processTracker = new();
    private readonly ProductionMemoryAnalyzer _memoryAnalyzer = new();
    private readonly PayloadAnalyzer _payloadAnalyzer = new();
    private readonly ResponseEngine _responseEngine = new();
    private readonly ConcurrentQueue<DetectionEvent> _recentDetections = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly object _statisticsLock = new();
    private ManagementEventWatcher? _processStartWatcher;
    private ManagementEventWatcher? _processStopWatcher;

    private long _packetsInspected;
    private long _blockedConnections;
    private long _processesTracked;
    private long _memoryScans;
    private long _confirmedThreats;

    public async Task StartAsync()
    {
        await StartNetworkInterceptionAsync(_cts.Token).ConfigureAwait(false);
        await _reverseProxy.StartAsync(_cts.Token).ConfigureAwait(false);
        _reverseProxy.PayloadReady += OnPayloadReady;
        StartProcessWatchers();
        StartMemorySweep();
    }

    private async Task StartNetworkInterceptionAsync(CancellationToken token)
    {
        foreach (var adapter in NetworkAdapterManager.DetectAdapters())
        {
            var interceptor = new ProductionPacketInterceptor(adapter);
            interceptor.PacketCaptured += OnPacketCaptured;
            await interceptor.StartAsync(token).ConfigureAwait(false);
            _monitors.Add(interceptor);
        }
    }

    private void StartProcessWatchers()
    {
        _processStartWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        _processStopWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
        _processStartWatcher.EventArrived += (_, args) =>
        {
            var pid = Convert.ToInt32(args.NewEvent.Properties["ProcessID"].Value);
            Interlocked.Increment(ref _processesTracked);
            _ = Task.Run(() =>
            {
                try
                {
                    var result = _memoryAnalyzer.AnalyzeProcessMemory(pid);
                    Interlocked.Increment(ref _memoryScans);
                    EvaluateMemoryFindings(Process.GetProcessById(pid), result);
                }
                catch
                {
                }
            });
        };
        _processStopWatcher.EventArrived += (_, _) => Interlocked.Decrement(ref _processesTracked);
        _processStartWatcher.Start();
        _processStopWatcher.Start();
    }

    private void StartMemorySweep()
    {
        Task.Run(async () =>
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                foreach (var process in Process.GetProcesses().Where(p => !p.HasExited))
                {
                    try
                    {
                        var result = _memoryAnalyzer.AnalyzeProcessMemory(process.Id);
                        Interlocked.Increment(ref _memoryScans);
                        EvaluateMemoryFindings(process, result);
                    }
                    catch
                    {
                    }
                }

                await Task.Delay(TimeSpan.FromMinutes(5), _cts.Token).ConfigureAwait(false);
            }
        }, _cts.Token);
    }

    private void EvaluateMemoryFindings(Process process, MemoryAnalysisResult result)
    {
        if (result.SuspiciousStrings.Count == 0 && result.ApiHooks.Count == 0)
        {
            return;
        }

        var detection = new DetectionEvent(
            DateTime.UtcNow,
            process.ProcessName,
            new IPEndPoint(IPAddress.None, 0),
            "Abnormal memory indicators",
            "Log",
            0.65,
            result.SuspiciousStrings.Take(5).ToList());
        RegisterDetection(detection);
    }

    private void OnPacketCaptured(object? sender, PacketCapturedEventArgs e)
    {
        Interlocked.Increment(ref _packetsInspected);
        if (e.Protocol is "TCP" or "UDP")
        {
            AnalyzePayload(e.Payload, e.ProcessId, e.RemoteEndpoint);
        }
    }

    private void OnPayloadReady(object? sender, DecryptedPayloadEventArgs e)
    {
        AnalyzePayload(e.Payload, e.ProcessId, e.RemoteEndpoint);
    }

    private void AnalyzePayload(byte[] payload, int processId, IPEndPoint remote)
    {
        try
        {
            PacketRepository.AddPacket(processId, (byte[])payload.Clone(), remote);
            var context = _processTracker.GetProcessContext(processId);
            var workingCopy = (byte[])payload.Clone();
            var analysis = _payloadAnalyzer.Inspect(workingCopy, context);
            if (analysis.Indicators.Count == 0)
            {
                return;
            }

            var action = _responseEngine.Enforce(analysis, workingCopy);
            if (action is "Block connection" or "Terminate process")
            {
                Interlocked.Increment(ref _blockedConnections);
                Interlocked.Increment(ref _confirmedThreats);
            }

            var detection = new DetectionEvent(
                DateTime.UtcNow,
                context.RootProcess.ProcessName,
                remote,
                string.Join(", ", analysis.Indicators),
                action,
                0.9,
                analysis.Indicators);
            RegisterDetection(detection);
        }
        catch
        {
        }
    }

    private void RegisterDetection(DetectionEvent detection)
    {
        _recentDetections.Enqueue(detection);
        while (_recentDetections.Count > 50 && _recentDetections.TryDequeue(out _))
        {
        }
    }

    public SystemStatistics GetStatistics()
    {
        lock (_statisticsLock)
        {
            return new SystemStatistics(
                Interlocked.Read(ref _packetsInspected),
                Interlocked.Read(ref _blockedConnections),
                Interlocked.Read(ref _processesTracked),
                Interlocked.Read(ref _memoryScans),
                Interlocked.Read(ref _confirmedThreats),
                _recentDetections.ToArray());
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        foreach (var monitor in _monitors)
        {
            await monitor.StopAsync().ConfigureAwait(false);
            await monitor.DisposeAsync().ConfigureAwait(false);
        }

        await _reverseProxy.StopAsync().ConfigureAwait(false);
        _reverseProxy.PayloadReady -= OnPayloadReady;
        _processStartWatcher?.Stop();
        _processStartWatcher?.Dispose();
        _processStopWatcher?.Stop();
        _processStopWatcher?.Dispose();
        _cts.Dispose();
    }
}
