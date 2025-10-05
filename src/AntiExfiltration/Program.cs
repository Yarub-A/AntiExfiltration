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
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var configuration = AppConfiguration.Load();
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
            IntegrityChecker = integrityChecker
        });

        await integrityChecker.VerifyAsync(cts.Token).ConfigureAwait(false);
        certificateManager.Initialize();
        await pluginManager.LoadAsync(cts.Token).ConfigureAwait(false);

        var tasks = new List<Task>
        {
            processMonitor.RunAsync(cts.Token),
            memoryScanner.RunAsync(cts.Token),
            networkInterceptor.RunAsync(cts.Token),
            apiHookManager.RunAsync(cts.Token),
            consoleUi.RunAsync(cts.Token)
        };

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }
}
