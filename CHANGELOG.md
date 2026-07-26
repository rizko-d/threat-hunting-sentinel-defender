# Changelog

All notable changes to this threat-hunting library are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2026-07-26

### Added

- **Methodology** — the six-phase hunting loop (Trigger → Hypothesis → Scope →
  Hunt → Triage → Outcome), hypothesis framework with prioritization scoring, KQL
  hunting techniques reference, and triage/documentation + hunt→detection
  graduation criteria.
- **Data-sources reference** — Sentinel tables, Defender XDR Advanced Hunting
  schema, and key Windows event IDs.
- **9 Hunt Cards** across 7 ATT&CK tactics:
  - Credential Access — Kerberoasting (T1558.003), LSASS Dumping (T1003.001)
  - Execution — Obfuscated PowerShell (T1059.001)
  - Persistence — Suspicious Scheduled Task (T1053.005)
  - Defense Evasion — Event Log Clearing (T1070.001)
  - Discovery — AD Reconnaissance (T1087/T1069/T1482)
  - Lateral Movement — WMI (T1047)
  - Command and Control — C2 Beaconing (T1071.001)
  - Collection/Exfiltration — OAuth Consent & Mailbox Exfil (T1098.003/T1114)
- **ATT&CK coverage tracking** — coverage matrix, gap analysis, machine-readable
  `mitre-attack.yaml`.
- **Hunt Card template** for authoring new hunts.
- MIT license, GitHub Pages landing page.
