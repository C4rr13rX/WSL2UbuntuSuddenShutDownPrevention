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

## Diagnostic Enhancements

The current iteration introduces ten focused improvements that tighten attribution and elevate the fidelity of failure evidence:

1. **Channel-aware Windows event ingestion** — Hyper-V, WSL runtime, Defender, and WER channels are tailed with native severity derived from event levels so crash IDs and virtualization faults are surfaced immediately.
2. **Windows service health tracker** — Continuous status telemetry for `LxssManager`, `vmcompute`, `vmms`, and related services records PID churn, exit codes, and restart storms.
3. **WSL diagnostics snapshots** — Periodic `wsl.exe --status` and `wsl.exe -l -v` captures prove distro state and default version right before an outage.
4. **Crash artifact sweeps** — Windows Error Reporting queues and live kernel dump directories are monitored for new crash dumps with precise timestamps.
5. **Process memory pressure alerts** — Working set and commit growth for `vmmem`, `wslhost.exe`, and peers are translated into warning/critical events when resource usage spikes.
6. **Kernel message tap** — `/dev/kmsg` tailing on Ubuntu pushes panics, OOM traces, and fatal kernel warnings into the forensic log chain.
7. **Pressure stall analysis** — `/proc/pressure/{memory,cpu}` thresholds raise alerts for sustained contention that typically precedes forced terminations.
8. **Systemd failure reporting** — `systemctl --failed` deltas reveal unit-level regressions (e.g., journald, networkd) that might cascade into WSL stoppages.
9. **Network degradation detector** — Interface error/dropped packet counters expose host networking faults and VPN toggles that frequently reset WSL virtual NICs.
10. **Unified master report** — A cross-platform CLI merges host/guest logs, preserves tamper hashes, and outputs a chronological JSON dossier for downstream analytics.
11. **Post-restart heuristic analyzer** — After every reboot investigators can run the `master_report` CLI to surface restart bursts, third-party security interventions, memory pressure spikes, and kernel faults with curated supporting evidence.
12. **Third-party security suite insight** — The Windows service now queries `AntiVirusProduct`, `AntiSpywareProduct`, and `FirewallProduct` WMI providers and correlates the results with vendor-specific services (CrowdStrike, SentinelOne, Symantec, McAfee, and Trend Micro) so quarantines and policy enforcement gaps are visible immediately.
13. **Cross-channel health snapshot** — The generated report summarizes host/guest event totals by severity, bounding timestamps for each channel so teams can verify telemetry completeness at a glance.

## End-to-End Automation

Professional deployments rely on reproducible, scripted automation so investigators can rebuild agents, redeploy, and collect evidence without manual tweaks. The `scripts/` directory provides hardened automation for both operating systems. All toolchains are based on open-source projects (CMake, Ninja) or free Microsoft offerings (Visual Studio Build Tools, Windows SDK) so the project can be compiled without commercial licenses.

### Ubuntu (WSL Guest)

1. **Install prerequisites**

   ```bash
   ./scripts/ubuntu/install_dependencies.sh
   ```

   The installer retries transient APT failures, validates that CMake, Ninja, and GCC are present, and adds the `libsystemd-dev` headers required for journal access.

2. **Compile**

   ```bash
   ./scripts/ubuntu/build.sh
   ```

   This generates a Ninja build in `build/ubuntu/` and produces both the `wsl_monitor` daemon and the `master_report` CLI.

3. **Deploy & enable autostart**

   ```bash
   sudo ./scripts/ubuntu/deploy.sh
   ```

   Deployment installs the daemon to `/usr/local/sbin/wsl-monitor`, provisions `/var/log/wsl-monitor` with restrictive permissions, installs the hardened systemd unit, and enables it to launch on boot.

### Windows 11 Host

1. **Install prerequisites (elevated PowerShell)**

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   ./scripts/windows/install_dependencies.ps1
   ```

   The script provisions Visual Studio 2022 Build Tools with the C++ workload, CMake, Ninja, and Git using winget. If winget is unavailable it downloads the Microsoft Build Tools bootstrapper directly.

2. **Compile**

   ```powershell
   ./scripts/windows/build.ps1
   ```

   A Visual Studio solution is generated under `build\windows` and built in Release mode.

3. **Deploy & enable autostart (elevated PowerShell)**

   ```powershell
   ./scripts/windows/deploy.ps1
   ```

   Deployment copies binaries into `C:\Program Files\WslMonitor`, prepares `C:\ProgramData\WslMonitor` for tamper-evident logs, registers the `WslShutdownMonitor` Windows service under `LocalService`, configures automatic recovery, and starts the service immediately.

### Master Report Aggregation

Both build systems emit the cross-platform `master_report` CLI. After telemetry is captured on each side, investigators can consolidate evidence:

```bash
"/usr/local/bin/wsl-master-report" \
  --host-log /mnt/c/ProgramData/WslMonitor/host-events.log \
  --guest-log /var/log/wsl-monitor/guest-events.log \
  --output /tmp/wsl-master-report.json
```

On Windows, the same binary is deployed to `C:\Program Files\WslMonitor\master_report.exe` and accepts identical arguments.

The resulting JSON includes host/guest metadata, final hash-chain anchors, and an event list sorted by timestamp that is ready for downstream AI or investigator review.

When the CLI runs post-restart it also computes a heuristic summary under the `analysis` section. Each insight lists the confidence rating and serializes the supporting events so the team can triage suspicious sequences quickly without manually scanning the raw logs. The sibling `health` section captures per-channel counts and observation windows to verify that telemetry was captured across the entire outage window.

### Host/Guest Bridge

The Windows service exposes `\\.\pipe\WslMonitorBridge` while the Ubuntu daemon listens on `/var/run/wsl-monitor/host.sock`. Deployment scripts generate or sync a 32-byte secret to `C:\ProgramData\WslMonitor\ipc.key` and `/etc/wsl-monitor/ipc.key`. Each connection performs a nonce/HMAC handshake before exchanging HMAC-authenticated event frames. Relayed records are logged locally with a `peer_origin` attribute so investigators can trace whether evidence originated on the host or in the guest.

## Quality gates

This repository now ships with a lightweight regression test that exercises the heuristic analyzer and cross-channel metrics. Execute the top-level CMake build and invoke `ctest` to confirm that the analyzer surfaces the expected insights:

```bash
cmake -S . -B build/full
cmake --build build/full
ctest --test-dir build/full
```

## Security & Forensic Guarantees

- Agents run with least privileges required to read system telemetry. On Windows, the service runs under `LocalService` with the `SeAuditPrivilege` and `SeSecurityPrivilege` rights to subscribe to security logs. On Ubuntu, the daemon leverages `CAP_DAC_READ_SEARCH` to read `/var/log` entries without full root access and tightens directory ACLs for all evidence paths.
- Every log entry is wrapped in a tamper-evident envelope. The shared logger maintains a SHA-256 hash chain, persists chain state across restarts, and can optionally add an HMAC-SHA256 signature when `WSLMON_LOG_HMAC_KEY` (hex string) or `WSLMON_LOG_HMAC_KEY_FILE` (path to file containing hex-encoded key material) is provided. Rotated logs emit a JSON manifest recording the final chain hash, rotation timestamp, and entry count.
- Host identity metadata (hostname, machine/boot IDs) is attached automatically so investigators can prove provenance without out-of-band lookup tables.
- Windows and Ubuntu agents exchange telemetry over a mutually authenticated channel that pairs a Windows named pipe with an Ubuntu AF_UNIX socket. A shared secret established during deployment drives nonce-based HMAC handshakes, and every relayed event is wrapped in an authenticated frame before it is logged on the receiving side.

See [`docs/forensics_gap_analysis.md`](docs/forensics_gap_analysis.md) for a detailed comparison between the prototype baseline and the hardened, forensics-ready posture.

