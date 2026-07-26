# Changelog

All notable changes to this threat-hunting library are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [1.4.0] - 2026-07-26

### Added

- **6 new Hunt Cards** — Collection + standalone Exfiltration, to 24 hunts / 12 tactics:
  - Collection: Screen Capture & Clipboard (T1113/T1115), Archive for Staging (T1560.001), Automated Collection from Shares (T1119/T1039)
  - Exfiltration: Over C2 Channel (T1041), To Cloud Storage (T1567.002), Over Alternative Protocol/DNS (T1048/.003)
- **Purple-team Validation section on every Hunt Card** — Atomic Red Team test / lab-simulation reference + expected-hit, so each hunt is verifiable before you rely on it.
- **Kill-chain hunt-chaining playbook** (`methodology/04-hunt-chaining-killchain.md`) — correlated intrusion stories showing how hunts chain end-to-end.
- **Sentinel deployment tooling** (`deploy/`) — ARM templates + `Deploy-Hunts.ps1` to push hunts as Scheduled Analytic Rules or saved Hunting Queries.

### Changed

- Updated README, ATTACK_MATRIX, coverage tracking, and `mitre-attack.yaml` to
  reflect 24 hunts across 12 ATT&CK tactics; split the former "Collection /
  Exfiltration (cloud)" grouping into distinct Collection and Exfiltration sections.

## [1.3.0] - 2026-07-26

### Added

- **3 Initial Access Hunt Cards** — closing the kill-chain to 10 tactics / 18 hunts:
  - Phishing Delivery via Malicious Mail (T1566.001/002) — delivered dangerous attachments + link/auth-fail hunting
  - Public-Facing App Exploitation & Web Shell (T1190/T1505.003) — web-process→shell + web-shell-on-disk + IIS POST hunting
  - Malicious Attachment / Link User Execution (T1204.001/002) — Office/browser→interpreter + downloads/ISO execution
- The three link delivery → user execution → payload/C2, joining the front of the
  kill-chain to the existing Execution/C2/Impact cards.

### Changed

- Updated README, ATTACK_MATRIX, coverage tracking, and `mitre-attack.yaml` to
  reflect 18 hunts across 10 ATT&CK tactics.

## [1.2.0] - 2026-07-26

### Added

- **3 Privilege Escalation Hunt Cards** — expanding coverage to 9 tactics / 15 hunts:
  - UAC Bypass via Auto-Elevated Binary Hijack (T1548.002) — fodhelper/eventvwr/sdclt + registry hijack keys
  - Access Token Manipulation & Parent-PID Spoofing (T1134) — SYSTEM-integrity mismatch, named-pipe impersonation
  - DLL Search-Order & Phantom DLL Hijacking (T1574.001/002) — unsigned DLL from non-system path + plant→load correlation

### Changed

- Updated README, ATTACK_MATRIX, coverage tracking, and `mitre-attack.yaml` to
  reflect 15 hunts across 9 ATT&CK tactics.

## [1.1.0] - 2026-07-26

### Added

- **3 Impact (ransomware) Hunt Cards** — expanding coverage to 8 tactics / 12 hunts:
  - Shadow Copy Deletion — Inhibit System Recovery (T1490)
  - Mass File Modification / Ransomware Encryption (T1486)
  - Service Stop & Recovery Tampering — Pre-Encryption (T1489/T1490)
- The three chain together as the ransomware kill-chain shape: service stop →
  shadow delete → mass encrypt, with cross-references between the cards.

### Changed

- Updated README, ATTACK_MATRIX, coverage tracking, and `mitre-attack.yaml` to
  reflect 12 hunts across 8 ATT&CK tactics.

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
