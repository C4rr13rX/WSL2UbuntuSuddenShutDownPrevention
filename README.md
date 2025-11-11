# WSL2 Sudden Shutdown Prevention Toolkit

This repository hosts native monitoring agents for Windows 11 hosts and Ubuntu distributions running inside WSL2. The agents are designed to run as services/daemons that collect high-fidelity telemetry leading up to unexpected WSL shutdowns. Captured telemetry is written in a structured JSON format that can be correlated across environments.

## Repository Layout

- `shared/` — Cross-platform utilities used by both agents (logging helpers, event buffering, configuration schema).
- `windows/` — Windows 11 native service that captures OS, hypervisor, security, and virtualization telemetry.
- `ubuntu/` — Ubuntu (WSL2) native daemon that tails critical logs and monitors key subsystems.
- `docs/` — Operational documentation and reference material.

## High-level Goals

1. **Detect** subsystems that influence WSL lifecycle (power events, virtualization service crashes, antivirus interventions, kernel panics, etc.).
2. **Capture** granular event metadata leading up to termination.
3. **Persist** events in a tamper-resistant rolling store with timestamps synchronized between Windows and Ubuntu.
4. **Report** correlations immediately after restart to surface probable causes.

## Build Instructions (Overview)

### Ubuntu Agent

```bash
sudo apt install cmake g++ libsystemd-dev
cmake -S ubuntu -B build/ubuntu
cmake --build build/ubuntu --config Release
```

Install the service:

```bash
sudo cp build/ubuntu/wsl_monitor /usr/local/sbin/wsl-monitor
sudo cp ubuntu/systemd/wsl-monitor.service /etc/systemd/system/
sudo systemctl enable --now wsl-monitor
```

### Windows Agent

1. Install **Desktop development with C++** workload in Visual Studio 2022.
2. Open a `x64 Native Tools Command Prompt` and run:

```bat
cmake -S windows -B build\windows -G "Visual Studio 17 2022" -A x64
cmake --build build\windows --config Release
```

3. Install the service (from elevated prompt):

```bat
sc create WslShutdownMonitor binPath= "C:\\Program Files\\WslMonitor\\WslShutdownMonitor.exe" start= auto
sc start WslShutdownMonitor
```

## Security Considerations

- Agents run with least privileges required to read system telemetry. On Windows, the service runs under `LocalService` with the `SeAuditPrivilege` and `SeSecurityPrivilege` rights to subscribe to security logs. On Ubuntu, the daemon leverages `CAP_DAC_READ_SEARCH` to read `/var/log` entries without full root access.
- Logs are written in append-only mode with periodic hashing to detect tampering.
- Communication between host and guest agents will be added via mutually authenticated named pipes/AF_UNIX sockets in a follow-up iteration.

## Next Steps

- Implement secure cross-environment synchronization channel.
- Add heuristic analyzer that runs post-restart to correlate events.
- Expand coverage for third-party security suites through vendor-specific APIs.

