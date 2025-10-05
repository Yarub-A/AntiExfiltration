using AntiExfiltration.Infrastructure;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;

namespace AntiExfiltration.Plugins;

[SupportedOSPlatform("windows")]
public sealed class PluginManager
{
    private readonly SecureLogger _logger;
    private readonly string _pluginDirectory;
    private readonly List<IDetectionPlugin> _plugins = new();

    public PluginManager(SecureLogger logger, string pluginDirectory)
    {
        _logger = logger;
        _pluginDirectory = pluginDirectory;
        Directory.CreateDirectory(_pluginDirectory);
    }

    public IReadOnlyCollection<IDetectionPlugin> ActivePlugins => _plugins;

    public async Task LoadAsync(CancellationToken token)
    {
        foreach (var file in Directory.EnumerateFiles(_pluginDirectory, "*.dll"))
        {
            try
            {
                var assembly = Assembly.LoadFrom(file);
                foreach (var pluginType in assembly.GetTypes().Where(t => typeof(IDetectionPlugin).IsAssignableFrom(t) && !t.IsAbstract))
                {
                    if (Activator.CreateInstance(pluginType) is IDetectionPlugin plugin)
                    {
                        await plugin.InitializeAsync(token).ConfigureAwait(false);
                        _plugins.Add(plugin);
                        _logger.Log(new
                        {
                            timestamp = DateTimeOffset.UtcNow,
                            eventType = "pluginLoaded",
                            plugin = pluginType.FullName
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Log(new
                {
                    timestamp = DateTimeOffset.UtcNow,
                    eventType = "pluginLoadFailed",
                    file,
                    ex.Message
                });
            }
        }
    }
}

public interface IDetectionPlugin
{
    Task InitializeAsync(CancellationToken token);

    IEnumerable<PluginAlert> AnalyzeProcess(int processId, string processName, string commandLine, string executablePath);
}

public sealed record PluginAlert(string Indicator, int Score);
