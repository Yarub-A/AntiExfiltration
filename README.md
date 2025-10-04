# AntiExfiltration

Comprehensive Windows data-exfiltration protection solution that combines network interception, memory analysis, and real-time process tracking. The project includes an elevated service and a feature-rich monitoring console.

## Project layout

```
AntiExfiltrationSystem.sln
└── src/AntiExfiltrationSystem
    ├── Program.cs
    ├── Core/            # detection engines and orchestration
    ├── Detection/       # payload analysis & responses
    ├── Infrastructure/  # console UI and helpers
    ├── Memory/          # memory & heap analysis
    ├── Networking/      # packet capture and reverse proxy
    ├── ProcessMonitoring/# process context and tracking
    ├── ReverseProxy/    # real-time TLS interception
    ├── ThreatIntel/     # threat intelligence integrations
    └── Utilities/       # shared helpers
```

## System requirements

* Windows 10/11 x64
* Administrator or SYSTEM privileges
* .NET SDK 8.0 (Windows-supported)
* Free port for the reverse-proxy (default: 8443)

## Setup & run

1. Restore packages

```powershell
dotnet restore AntiExfiltrationSystem.sln
```

2. Build (Release)

```powershell
dotnet build AntiExfiltrationSystem.sln -c Release -f net8.0-windows
```

3. Publish (self-contained, optional)

```powershell
dotnet publish src/AntiExfiltrationSystem/AntiExfiltrationSystem.csproj -c Release -r win-x64 -f net8.0-windows --self-contained true
```

4. Run elevated

```powershell
Start-Process "./bin/Release/net8.0-windows/AntiExfiltrationSystem.exe" -Verb RunAs
```

> If you built for another target framework, update the path accordingly.

## Key features

* True packet interception using raw sockets / platform capture drivers
* Reverse proxy with TLS interception and dynamic certificate injection
* Real-time process tracking (WMI / native APIs)
* Advanced memory analysis and sensitive string extraction
* Automated responses (log, obfuscate, block, terminate)
* Live console UI with filtering and controls

## Security & best practices

* A private root CA is generated and securely stored in the local certificate store
* Suspicious connections may be reset (TCP RST) or the originating process terminated
* Sensitive data is zeroed in memory during processing
* Full auditing and logging are maintained for post-event analysis

## Testing guidance

* Use a dedicated lab or VM with representative traffic for interception tests
* Inject test payloads (passwords, API keys) into target processes to validate detection
* Create leak scenarios (e.g. uploading JSON with secrets) to verify automated responses

**Note:** Install and run on a Windows host or VM. The current environment is Linux and suitable only for code editing.
