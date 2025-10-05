using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiExfiltration.Core;

public sealed record AppConfiguration(
    string LoggingDirectory,
    string PluginDirectory,
    BehaviorConfiguration Behavior,
    CertificateConfiguration Certificate,
    IntegrityConfiguration Integrity,
    DefenseConfiguration Defense,
    ProcessMonitoringConfiguration ProcessMonitoring,
    MemoryScanningConfiguration MemoryScanning,
    NetworkConfiguration Network,
    ApiHookConfiguration ApiHooks,
    UiConfiguration Ui)
{
    private const string ConfigurationFile = "config.json";

    public static AppConfiguration Load()
    {
        if (!File.Exists(ConfigurationFile))
        {
            var defaults = CreateDefaults();
            var json = JsonSerializer.Serialize(defaults, JsonSerializerOptions);
            File.WriteAllText(ConfigurationFile, json);
            return defaults;
        }

        var content = File.ReadAllText(ConfigurationFile);
        return JsonSerializer.Deserialize<AppConfiguration>(content, JsonSerializerOptions)
               ?? CreateDefaults();
    }

    private static AppConfiguration CreateDefaults() => new(
        LoggingDirectory: Path.Combine(AppContext.BaseDirectory, "logs"),
        PluginDirectory: Path.Combine(AppContext.BaseDirectory, "plugins"),
        Behavior: new BehaviorConfiguration(),
        Certificate: new CertificateConfiguration(),
        Integrity: new IntegrityConfiguration(),
        Defense: new DefenseConfiguration(),
        ProcessMonitoring: new ProcessMonitoringConfiguration(),
        MemoryScanning: new MemoryScanningConfiguration(),
        Network: new NetworkConfiguration(),
        ApiHooks: new ApiHookConfiguration(),
        Ui: new UiConfiguration());

    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}

public sealed record BehaviorConfiguration
{
    public int SuspiciousThreshold { get; init; } = 10;
    public int MaliciousThreshold { get; init; } = 15;
    public int CriticalThreshold { get; init; } = 20;
};

public sealed record CertificateConfiguration
{
    public string CertificateFriendlyName { get; init; } = "AntiExfiltration Root";
    public bool InstallToLocalMachine { get; init; }
        = false;
};

public sealed record IntegrityConfiguration
{
    public string[] ProtectedFiles { get; init; } = new[] { "AntiExfiltration.exe", "config.json" };
    public TimeSpan VerificationInterval { get; init; } = TimeSpan.FromMinutes(5);
};

public sealed record DefenseConfiguration
{
    public TimeSpan ProcessSuspendDuration { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan NetworkBlockDuration { get; init; } = TimeSpan.FromMinutes(5);
};

public sealed record ProcessMonitoringConfiguration
{
    public TimeSpan ScanInterval { get; init; } = TimeSpan.FromSeconds(5);
    public string[] AllowListedProcesses { get; init; } = new[] { "chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe" };
};

public sealed record MemoryScanningConfiguration
{
    public TimeSpan ScanInterval { get; init; } = TimeSpan.FromSeconds(30);
    public int MaxConcurrentScans { get; init; } = 5;
    public string[] TargetProcesses { get; init; } = new[] { "chrome.exe", "msedge.exe", "firefox.exe" };
};

public sealed record NetworkConfiguration
{
    public TimeSpan ScanInterval { get; init; } = TimeSpan.FromSeconds(3);
    public string PrimaryInterfacePreference { get; init; } = "Wi-Fi";
    public string[] HighRiskHosts { get; init; } = new[]
    {
        "telegram.org",
        "discord.com",
        "cloudflare-dns.com"
    };
};

public sealed record ApiHookConfiguration
{
    public string[] TargetProcesses { get; init; } = new[] { "chrome.exe", "msedge.exe", "firefox.exe" };
};

public sealed record UiConfiguration
{
    public TimeSpan RefreshInterval { get; init; } = TimeSpan.FromSeconds(1);
};
