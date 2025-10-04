using AntiExfiltrationSystem.Core;
using AntiExfiltrationSystem.Infrastructure;

namespace AntiExfiltrationSystem;

internal static class Program
{
    private static async Task Main()
    {
        var console = new ProductionConsole();
        await console.StartAsync();
    }
}
