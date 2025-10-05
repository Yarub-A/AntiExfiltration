using AntiExfiltration.Infrastructure;
using System.Collections.Concurrent;
using System.Linq;
using System.Runtime.Versioning;

namespace AntiExfiltration.Core;

[SupportedOSPlatform("windows")]
public sealed class MonitoringHost : IDisposable
{
    private readonly SecureLogger _logger;
    private readonly ConcurrentDictionary<string, Func<CancellationToken, Task>> _workers = new();
    private readonly object _stateLock = new();

    private CancellationTokenSource? _cts;
    private Task[]? _runningTasks;

    public MonitoringHost(SecureLogger logger)
    {
        _logger = logger;
    }

    public MonitoringState State { get; private set; } = MonitoringState.Stopped;

    public void Register(string name, Func<CancellationToken, Task> worker)
    {
        if (!_workers.TryAdd(name, worker))
        {
            throw new InvalidOperationException($"Worker '{name}' is already registered.");
        }
    }

    public void Start()
    {
        lock (_stateLock)
        {
            if (State == MonitoringState.Running)
            {
                return;
            }

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _runningTasks = _workers
                .Select(worker => Task.Run(() => RunWorkerAsync(worker.Key, worker.Value, token), token))
                .ToArray();
            State = MonitoringState.Running;
        }
    }

    public async Task StopAsync()
    {
        Task[]? running;
        lock (_stateLock)
        {
            if (State != MonitoringState.Running)
            {
                return;
            }

            State = MonitoringState.Stopping;
            _cts?.Cancel();
            running = _runningTasks;
        }

        if (running is not null)
        {
            try
            {
                await Task.WhenAll(running).ConfigureAwait(false);
            }
            catch
            {
                // ignored; worker failures are logged individually
            }
        }

        lock (_stateLock)
        {
            _cts?.Dispose();
            _cts = null;
            _runningTasks = null;
            State = MonitoringState.Stopped;
        }
    }

    public async Task RestartAsync()
    {
        await StopAsync().ConfigureAwait(false);
        Start();
    }

    private async Task RunWorkerAsync(string name, Func<CancellationToken, Task> worker, CancellationToken token)
    {
        try
        {
            await worker(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // graceful shutdown
        }
        catch (Exception ex)
        {
            _logger.Log(new
            {
                timestamp = DateTimeOffset.UtcNow,
                eventType = "monitoringWorkerFailed",
                worker = name,
                error = ex.Message
            });
        }
    }

    public void Dispose()
    {
        _ = StopAsync();
    }
}

public enum MonitoringState
{
    Stopped,
    Running,
    Stopping
}
