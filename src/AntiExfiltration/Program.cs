using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using AntiExfiltration.Monitoring;
using AntiExfiltration.Plugins;
using AntiExfiltration.Security;
using AntiExfiltration.UI;
using System.Runtime.Versioning;

namespace AntiExfiltration;

[SupportedOSPlatform("windows")]
public static class Program
{
    public static async Task Main(string[] args)
    {
        var configuration = AppConfiguration.Load();

        if (args.Length > 0 && args[0].Equals("--decode-log", StringComparison.OrdinalIgnoreCase))
        {
            var candidate = args.Length > 1 ? args[1] : null;
            var logPath = ResolveLogPath(configuration.LoggingDirectory, candidate);
            if (logPath is null)
            {
                Console.Error.WriteLine("No encrypted log files were found to decode.");
                return;
            }

            Environment.ExitCode = LogDecoder.DecodeToConsole(logPath);
            return;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var logger = new SecureLogger(configuration.LoggingDirectory);
        var behaviorEngine = new BehaviorEngine(logger, configuration.Behavior);
        var certificateManager = new CertificateManager(logger, configuration.Certificate);
        var pluginManager = new PluginManager(logger, configuration.PluginDirectory);
        var integrityChecker = new IntegrityChecker(logger, configuration.Integrity);
        var actionManager = new ActionManager(logger, behaviorEngine, configuration.Defense);
        var processMonitor = new ProcessMonitor(logger, behaviorEngine, actionManager, pluginManager, configuration.ProcessMonitoring);
        var memoryScanner = new MemoryScanner(logger, behaviorEngine, actionManager, configuration.MemoryScanning);
        var networkInterceptor = new NetworkInterceptor(logger, behaviorEngine, actionManager, configuration.Network);
        var apiHookManager = new ApiHookManager(logger, behaviorEngine, actionManager, configuration.ApiHooks);
        await integrityChecker.VerifyAsync(cts.Token).ConfigureAwait(false);
        certificateManager.Initialize();
        await pluginManager.LoadAsync(cts.Token).ConfigureAwait(false);

        using var monitoringHost = new MonitoringHost(logger);
        var loadMonitor = new SystemLoadMonitor(logger, configuration.LoadMonitoring, () => networkInterceptor.ActiveInterface);

        var consoleUi = new ConsoleUi(logger, configuration.Ui, new()
        {
            NetworkInterceptor = networkInterceptor,
            ProcessMonitor = processMonitor,
            MemoryScanner = memoryScanner,
            ApiHookManager = apiHookManager,
            PluginManager = pluginManager,
            BehaviorEngine = behaviorEngine,
            ActionManager = actionManager,
            CertificateManager = certificateManager,
            IntegrityChecker = integrityChecker,
            MonitoringHost = monitoringHost,
            LoadMonitor = loadMonitor,
            LogDirectory = configuration.LoggingDirectory
        });

        monitoringHost.Register("process-monitor", processMonitor.RunAsync);
        monitoringHost.Register("memory-scanner", memoryScanner.RunAsync);
        monitoringHost.Register("network-interceptor", networkInterceptor.RunAsync);
        monitoringHost.Register("api-hook-manager", apiHookManager.RunAsync);
        monitoringHost.Register("system-load", loadMonitor.RunAsync);

        monitoringHost.Start();

        var uiTask = consoleUi.RunAsync(cts.Token);
        await uiTask.ConfigureAwait(false);
        await monitoringHost.StopAsync().ConfigureAwait(false);
    }

    private static string? ResolveLogPath(string loggingDirectory, string? candidate)
    {
        if (!string.IsNullOrWhiteSpace(candidate))
        {
            return candidate;
        }

        if (!Directory.Exists(loggingDirectory))
        {
            return null;
        }

        return Directory
            .EnumerateFiles(loggingDirectory, "log-*.bin", SearchOption.TopDirectoryOnly)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }
}
