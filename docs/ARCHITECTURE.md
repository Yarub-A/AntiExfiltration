# Anti-Exfiltration Reference Architecture

## Overview
This document captures the software architecture for the Anti-Exfiltration pipeline. The solution is organised into composable modules that mirror the operational workflow: capture ➜ context ➜ policy ➜ decision ➜ enforcement ➜ logging/intel.

```
AntiExfiltration.sln
 ├─ src/
 │  ├─ AntiExfiltration.App/        # Console host + dependency wiring
 │  └─ AntiExfiltration.Core/       # Core library with modular components
 │       └─ src/
 │           ├─ Capture/            # Packet interception abstractions
 │           ├─ Context/            # Process metadata resolution
 │           ├─ Policy/             # Detection engines (signatures, entropy, etc.)
 │           ├─ Decision/           # Risk → action mapping
 │           ├─ Action/             # Enforcement orchestration
 │           ├─ Logging/            # Structured telemetry
 │           ├─ Intel/              # Threat intelligence integration
 │           └─ Pipeline/           # High-level coordinator
 └─ docs/
    └─ ARCHITECTURE.md
```

## Module Responsibilities

| Module | Purpose | Key Types |
|--------|---------|-----------|
| Capture | Intercept outbound traffic and surface events. | `ICaptureProvider`, `RawPacket` |
| Context | Resolve process lineage, signatures, and trust levels. | `IProcessContextResolver`, `ProcessInfo` |
| Policy | Analyse payloads and metadata to produce aggregated `AnalysisResult` instances. | `PolicyEngine`, `SignatureAnalyzer`, `EntropyAnalyzer`, `AnalyzerFinding` |
=======
| Policy | Analyse payloads and metadata to produce `AnalysisResult`. | `PolicyEngine`, `SignatureAnalyzer`, `EntropyAnalyzer` |
| Decision | Translate risk scores to enforcement outcomes. | `DecisionEngine`, `DecisionEngineOptions` |
| Action | Execute block/obfuscate/alert flows. | `ActionExecutor`, `IPacketDropper`, `IDataObfuscator`, `IProcessTerminator` |
| Logging | Persist forensic telemetry. | `IEventLogger`, `JsonEventLogger` |
| Intel | Synchronise third-party indicators and rules. | `IThreatIntelProvider`, `ThreatIntelManager` |
| Pipeline | Glue module orchestrating the flow. | `AntiExfiltrationPipeline` |

## Data Flow

1. `ICaptureProvider` raises `PacketCaptured` with a `RawPacket` payload.
2. `PolicyEngine` enriches the packet with `ProcessInfo`, runs analyzers sequentially, and merges their `AnalyzerFinding` outputs.
3. `AnalysisResult` (with merged evidence and risk) feeds into `DecisionEngine` which applies configurable default actions per `RiskLevel`.
=======
2. `PolicyEngine` enriches the packet with `ProcessInfo` and runs analyzers sequentially.
3. `AnalysisResult` feeds into `DecisionEngine` which applies configurable default actions per `RiskLevel`.
4. `ActionExecutor` enforces the decision and logs structured events.
5. `ThreatIntelManager` exposes IOC lookups and can be refreshed asynchronously.

## Extension Points

- Add custom analyzers by implementing `IAnalyzer` (e.g., ML models, DPI parsers).
- Swap `ICaptureProvider` with a WFP/ETW driver in production.
- Replace `IEventLogger` with a SIEM forwarder or database sink.
- Extend `ThreatIntelManager` to pull YARA/IOC feeds periodically.
- Introduce dashboards or REST APIs by reusing the Core library.

## Milestones (Suggested)

1. **Learning Mode**: Implement capture + logging only (no blocking).
2. **Signature Enforcement**: Enable `SignatureAnalyzer` + blocking for clear indicators.
3. **Advanced Analytics**: Add entropy/steganography modules and behavioural baselines.
4. **Operational Hardening**: Integrate with kernel drivers, secure storage, and tamper protection.
5. **Continuous Intelligence**: Automate feed ingestion and dashboards.
