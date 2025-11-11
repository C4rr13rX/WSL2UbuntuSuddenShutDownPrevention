# Architecture Overview

This project ships a pair of native telemetry agents that operate independently on the Windows 11 host and the Ubuntu distribution inside WSL2. Both agents persist detailed context for the minute leading up to a crash or shutdown, enabling investigators to reconstruct timelines across the virtualization boundary.

## Data Flow Summary

1. **Sensor Capture** — Each collector pulls from OS-native telemetry feeds (Windows Event Log, WMI, Systemd Journal, inotify, `/proc`).
2. **Normalization** — Events are normalized into a shared JSON schema (`EventRecord`) with consistent keys across operating systems.
3. **Local Persistence** — Events stream into append-only log files located at:
   - Windows: `C:\ProgramData\WslMonitor\host-events.log`
   - Ubuntu: `/var/log/wsl-monitor/guest-events.log`
4. **Rolling Buffer** — A 1,024-entry circular buffer keeps the most recent events in-memory to support rapid correlation once a cross-environment link is established.

## Windows Host Agent

The host agent runs as a Windows service (`WslShutdownMonitor`) and spawns specialized collectors:

- **EventLogCollector** — Monitors key channels including `System`, `Application`, Hyper-V operational logs, Windows Defender, and firewall activity. Each entry is captured as raw XML for precise parsing during analysis.
- **PowerCollector** — Samples AC line state, battery telemetry, and active power scheme to detect lid closures, sleep transitions, or policy enforcements that could terminate WSL instances.
- **ProcessCollector** — Tracks lifecycle events for `wsl.exe`, `vmmem`, `vmwp.exe`, and related processes to surface unexpected exits or restarts.
- **SecurityCollector** — Polls Windows Security Center (WMI) for antivirus product status, alerting investigators to security suites that may terminate WSL components.

All collectors feed structured events into the shared logger which performs log rotation at 5 MB.

## Ubuntu Guest Agent

The guest agent is a systemd service (`wsl-monitor`) that focuses on:

- **Journal Watcher** — Subscribes to the systemd journal, highlighting kernel transports, systemd services, oomd, and network services for early shutdown signals.
- **Resource Monitor** — Samples CPU, memory, and root filesystem pressure to detect resource exhaustion scenarios that could kill the distro or individual processes.
- **Crash Watcher** — Uses inotify to surface new entries under `/var/crash`, ensuring application faults are recorded immediately.

## Security Hardening

- Both agents write to dedicated directories with strict ACLs/permissions.
- Linux service is sandboxed via systemd hardening directives and capability bounding.
- Windows service runs under `LocalService` to minimize privilege exposure and only requests rights required for telemetry collection.

## Planned Integrations

- Cross-agent communication over a mutually authenticated channel (named pipes on Windows, AF_UNIX sockets on Ubuntu) for near-real-time correlation.
- Automated report generator that collates and summarizes the previous 60 seconds of host/guest activity after each restart.
- Additional collectors for GPU/driver telemetry, Windows Reliability Monitor (WER), and Linux kernel tracing hooks.

