# AntiExfiltration

AntiExfiltration is a Windows-focused defensive agent that monitors outbound traffic, process activity, and in-memory anomalies while persisting encrypted JSON audit logs.

## Requirements
- Windows 10 or later with administrative privileges.
- .NET 8 SDK.

## Build and Run
1. Clone the repository.
2. Build the solution:
   ```powershell
   dotnet build AntiExfiltration.sln -c Release
   ```
3. Launch the agent (run from an elevated PowerShell prompt):
   ```powershell
   dotnet run --project src/AntiExfiltration/AntiExfiltration.csproj -c Release
   ```
4. On first start the agent creates a local root certificate, `config.json`, and the `logs` / `plugins` directories next to the executable.

### Decoding encrypted logs
Use the built-in decoder to convert encrypted entries into plain JSON:
```powershell
dotnet run --project src/AntiExfiltration/AntiExfiltration.csproj -c Release -- --decode-log
```
By default the decoder locates the newest log file in the configured `logs` folder. To target a specific file:
```powershell
dotnet run --project src/AntiExfiltration/AntiExfiltration.csproj -c Release -- --decode-log "C:\\Path\\to\\log-20251005.bin"
```
Run the decoder with the same Windows account that executed the agent so DPAPI can unprotect the key file.

## Core Components
- **SecureLogger**: AES-256 encrypted JSON logging protected with DPAPI.
- **BehaviorEngine**: Aggregates indicators into per-process risk scores and tiers.
- **NetworkInterceptor**: Reads the TCP table, correlates connections to processes, and scores destinations.
- **ProcessMonitor**: Tracks command lines, signatures, and suspicious indicators for each process.
- **MemoryScanner**: Inspects high-risk processes for RWX pages using VirtualQueryEx.
- **ApiHookManager**: Observes allow-listed applications and records loaded modules.
- **IntegrityChecker**: Verifies protected binaries and configuration files.
- **PluginManager**: Loads custom detection plugins from the `plugins` directory.
- **ConsoleUi**: Command-driven dashboard for switching interfaces, listing telemetry, and triggering checks.
- **LogDecoder**: Command-line utility that decrypts log files using the stored DPAPI-protected key.

## Security Notes
- All analysis stays on the local device; no telemetry is transmitted externally.
- The agent never injects into protected Windows system processes.
- Encrypted logs and the DPAPI-protected `log.key` file remain in the `logs` folder and should be secured with NTFS ACLs.

## Testing
The solution relies on Windows APIs (WFP, DPAPI, WMI, VirtualQueryEx). Automated tests are not included because the instrumentation requires elevated privileges on Windows hosts.
