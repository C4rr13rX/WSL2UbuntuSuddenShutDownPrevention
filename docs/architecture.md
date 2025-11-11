# Architecture Overview

This project ships a pair of native telemetry agents that operate independently on the Windows 11 host and the Ubuntu distribution inside WSL2. Both agents persist detailed context for the minute leading up to a crash or shutdown, enabling investigators to reconstruct timelines across the virtualization boundary.

## Data Flow Summary

1. **Sensor Capture** — Each collector pulls from OS-native telemetry feeds (Windows Event Log, WMI, Systemd Journal, inotify, `/proc`).
2. **Normalization** — Events are normalized into a shared JSON schema (`EventRecord`) with consistent keys across operating systems.
3. **Local Persistence** — Events stream into append-only log files located at:
   - Windows: `C:\ProgramData\WslMonitor\host-events.log`
   - Ubuntu: `/var/log/wsl-monitor/guest-events.log`
4. **Rolling Buffer** — A 1,024-entry circular buffer keeps the most recent events in-memory to support rapid correlation once a cross-environment link is established.

5. **Master Report CLI** — The `master_report` tool ingests both logs, preserves per-line chain hashes, and emits a merged JSON package suitable for ingestion by downstream automation or AI triage.

## Windows Host Agent

The host agent runs as a Windows service (`WslShutdownMonitor`) and spawns specialized collectors:

- **EventLogCollector** — Monitors `System`, `Application`, Hyper-V operational feeds, Defender, firewall, WSL (`Microsoft-Windows-Lxss*`) and WER channels. Event severity is mapped directly from the Windows event level, ensuring virtualization or crash IDs arrive with proper criticality.
- **PowerCollector** — Samples AC line state, battery telemetry, and active power scheme to detect lid closures, sleep transitions, or policy enforcements that could terminate WSL instances.
- **ProcessCollector** — Tracks lifecycle events for `wsl.exe`, `wslhost.exe`, `vmmem`, and `vmwp.exe`, emitting warnings when working sets or commit usage surge above configurable thresholds.
- **SecurityCollector** — Polls Windows Security Center (WMI) for antivirus product status, alerting investigators to security suites that may terminate WSL components.
- **ServiceHealthCollector** — Watches `LxssManager`, `LxssManagerUser`, `vmcompute`, and `vmms` for PID churn, restarts, and exit codes.
- **WslDiagnosticCollector** — Periodically executes `wsl.exe --status` and `wsl.exe -l -v` to snapshot distro state, default versions, and engine health.
- **WerCollector** — Tails Windows Error Reporting queues and `C:\Windows\LiveKernelReports` for new dumps that often accompany abrupt shutdowns.

All collectors feed structured events into the shared logger which performs log rotation at 5 MB.

## Ubuntu Guest Agent

The guest agent is a systemd service (`wsl-monitor`) that focuses on:

- **Journal Watcher** — Subscribes to the systemd journal, highlighting kernel transports, systemd services, oomd, and network services for early shutdown signals.
- **Resource Monitor** — Samples CPU, memory, and root filesystem pressure to detect resource exhaustion scenarios that could kill the distro or individual processes.
- **Crash Watcher** — Uses inotify to surface new entries under `/var/crash`, ensuring application faults are recorded immediately.
- **Kernel Message Tap** — Streams `/dev/kmsg` to capture kernel panics, BUG traces, and OOM diagnostics as soon as they are emitted.
- **Pressure Stall Monitor** — Evaluates `/proc/pressure/{memory,cpu}` for sustained contention that typically precedes SIGKILL or forced shutdowns.
- **Systemd Failure Watcher** — Reports `systemctl --failed` deltas so service-level degradations (journald, networkd, etc.) are visible.
- **Network Health Watcher** — Flags drops/errors in `/proc/net/dev` counters for virtual interfaces such as `eth0`.

## Security Hardening

- Both agents write to dedicated directories with strict ACLs/permissions.
- Linux service is sandboxed via systemd hardening directives and capability bounding.
- Windows service runs under `LocalService` to minimize privilege exposure and only requests rights required for telemetry collection.

## Evidence Integrity Path

- The shared logging layer issues tamper-evident envelopes that combine a rolling SHA-256 hash chain with optional HMAC-SHA256 signatures derived from an operator-supplied key (`WSLMON_LOG_HMAC_KEY` or `WSLMON_LOG_HMAC_KEY_FILE`).
- Rotation produces sidecar manifests (`*.manifest`) that record the terminal chain hash, event count, and rotation timestamp for downstream chain-of-custody validation.
- State files (`*.chainstate`) persist the last hash and sequence counter so service restarts resume the chain without gaps.
- Ubuntu and Windows emitters automatically attach stable host identifiers (boot ID, machine ID/GUID, hostname) to every event to establish provenance.

## Planned Integrations

- Cross-agent communication over a mutually authenticated channel (named pipes on Windows, AF_UNIX sockets on Ubuntu) for near-real-time correlation.
- Automated remediation hooks (e.g., preemptive memory ballooning or graceful shutdown scripts) once dominant root causes are confirmed.
- Additional collectors for GPU/driver telemetry and Linux kernel tracing hooks.

