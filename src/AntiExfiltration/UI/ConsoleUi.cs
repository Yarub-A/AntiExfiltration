using AntiExfiltration.Core;
using AntiExfiltration.Infrastructure;
using AntiExfiltration.Monitoring;
using AntiExfiltration.Plugins;
using AntiExfiltration.Security;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace AntiExfiltration.UI;

[SupportedOSPlatform("windows")]
public sealed class ConsoleUi
{
    private readonly SecureLogger _logger;
    private readonly UiConfiguration _configuration;
    private readonly UiContext _context;

    public ConsoleUi(SecureLogger logger, UiConfiguration configuration, UiContext context)
    {
        _logger = logger;
        _configuration = configuration;
        _context = context;
    }

    public async Task RunAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            Render();
            await Task.Delay(_configuration.RefreshInterval, token).ConfigureAwait(false);
        }
    }

    private void Render()
    {
        Console.Clear();
        Console.WriteLine("=== AntiExfiltration Defender ===");
        Console.WriteLine($"Interface: {_context.NetworkInterceptor.ActiveInterface?.Name ?? "N/A"}");
        Console.WriteLine();

        Console.WriteLine("[Active Processes]");
        foreach (var process in _context.ProcessMonitor.SnapshotProcesses().OrderBy(p => p.ProcessId).Take(10))
        {
            var score = _context.BehaviorEngine.GetScore(process.ProcessId);
            Console.WriteLine($"PID {process.ProcessId} {process.Name} Score: {score.Total} Level: {score.Level}");
        }

        Console.WriteLine();
        Console.WriteLine("[Hooked Processes]");
        foreach (var hook in _context.ApiHookManager.HookedProcesses.Values)
        {
            Console.WriteLine($"PID {hook.ProcessId} Modules: {string.Join(',', hook.Modules.Take(5))}");
        }

        Console.WriteLine();
        Console.WriteLine("[Options]");
        Console.WriteLine("1) Switch Interface  2) List Interfaces  3) Run Integrity Check  4) Exit");
        if (!Console.KeyAvailable)
        {
            return;
        }

        var key = Console.ReadKey(intercept: true);
        switch (key.Key)
        {
            case ConsoleKey.D1:
            case ConsoleKey.NumPad1:
                Console.Write("Interface name: ");
                var name = Console.ReadLine();
                if (!string.IsNullOrWhiteSpace(name))
                {
                    _context.NetworkInterceptor.SwitchInterface(name);
                }
                break;
            case ConsoleKey.D2:
            case ConsoleKey.NumPad2:
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    Console.WriteLine($"- {iface.Name} ({iface.NetworkInterfaceType})");
                }
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey(true);
                break;
            case ConsoleKey.D3:
            case ConsoleKey.NumPad3:
                _ = _context.IntegrityChecker.VerifyAsync(CancellationToken.None);
                break;
            case ConsoleKey.D4:
            case ConsoleKey.NumPad4:
                Environment.Exit(0);
                break;
        }
    }
}

public sealed class UiContext
{
    public required NetworkInterceptor NetworkInterceptor { get; init; }
    public required ProcessMonitor ProcessMonitor { get; init; }
    public required MemoryScanner MemoryScanner { get; init; }
    public required ApiHookManager ApiHookManager { get; init; }
    public required PluginManager PluginManager { get; init; }
    public required BehaviorEngine BehaviorEngine { get; init; }
    public required ActionManager ActionManager { get; init; }
    public required CertificateManager CertificateManager { get; init; }
    public required IntegrityChecker IntegrityChecker { get; init; }
}
