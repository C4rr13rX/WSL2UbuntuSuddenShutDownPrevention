# Forensic Readiness Uplift

This document summarizes the delta between the initial prototype monitoring stack and the hardened
variant required by a digital forensics organization. It highlights the upgrades implemented in this
iteration and the residual items that should be captured on the delivery checklist.

## Capability Comparison

| Area | Prototype Baseline | Forensics-Grade Uplift |
| --- | --- | --- |
| **Log Integrity** | Plain JSON lines rotated at 5 MB without verification. | Each entry is wrapped in a tamper-evident envelope that includes a SHA-256 hash chain, optional HMAC-SHA256 signature, and rotation manifest for chain-of-custody. |
| **Key Management** | No signing material. | Supports operator-supplied signing keys via `WSLMON_LOG_HMAC_KEY` or `WSLMON_LOG_HMAC_KEY_FILE`; state files track sequence counters and chain hashes for audit continuity. |
| **Identity & Attribution** | Limited context; events only carried subsystem-specific fields. | Every record is auto-enriched with host identifiers (hostname, machine GUID/ID, boot ID) so investigators can prove provenance without external lookup tables. |
| **Service Hardening** | Default filesystem permissions and runtime isolation. | Log directories created with restrictive ACLs on Linux; Windows services run with least privilege and capture security center status (existing). Remaining gaps noted below. |
| **Configuration Governance** | Static paths compiled into binaries. | Runtime key ingestion documented and versioned; rotation manifests provide evidence packages for archival workflows. |
| **Documentation** | High-level architecture overview. | Added forensic readiness brief outlining controls, validation steps, and operational expectations for enterprise responders. |

## New Detection Controls

- **WSL-aware event ingestion** captures Hyper-V, Lxss, and WER diagnostics with native severity mapping so virtualization and crash artifacts are elevated immediately.
- **Service and crash observability** adds `ServiceHealthCollector`, on-demand `wsl.exe` diagnostics, and WER/live kernel dump sweeps to pinpoint host-side initiators.
- **Guest resiliency probes** monitor kernel messages, resource/pressure stalls, systemd unit failures, and network error counters to flag in-distro root causes.
- **Master report generation** merges Windows and Ubuntu evidence with preserved hash-chain anchors for turnkey AI or analyst review.

## Remaining Enterprise Checklist Items

The following should be scheduled with corporate security engineering to reach full certification:

1. **Secure key provisioning** — Integrate with the organization key vault (e.g., Azure Key Vault, HashiCorp Vault) instead of environment variables for long-term secret storage.
2. **Immutable storage targets** — Replicate rotated logs and manifests into WORM-compliant storage (object lock, SIEM ingestion) within defined SLAs.
3. **Operational runbooks** — Formalize key rotation cadence, signing key custody, and manifest retention inside the incident response playbook.
4. **Third-party suite integrations** — Expand Windows collectors to call vendor APIs for CrowdStrike, Carbon Black, and Microsoft Defender for Endpoint (roadmap).
5. **Automated validation** — Add CI enforcement that runs unit tests over the crypto envelope, checks manifest integrity, and enforces formatting.
6. **Packaging and deployment** — Produce signed MSIX/MSI packages for Windows and signed Debian packages for Ubuntu to align with enterprise software distribution policies.
7. **Time synchronization audits** — Integrate NTP health monitoring and cross-check drift to sustain correlated timelines across host/guest.

These tasks, combined with the code changes in this branch, establish a verifiable, chain-of-custody aware telemetry pipeline appropriate for high-assurance investigations.

