# How I Do Threat Hunting in Microsoft Sentinel & Defender XDR

**A hypothesis-driven threat hunting methodology and KQL hunt library for Microsoft Sentinel and Microsoft Defender XDR (Advanced Hunting).**

[![validate-hunts](https://github.com/rizko-d/threat-hunting-sentinel-defender/actions/workflows/validate.yml/badge.svg)](https://github.com/rizko-d/threat-hunting-sentinel-defender/actions/workflows/validate.yml)

> **License:** MIT · **Platform:** Microsoft Sentinel + Defender XDR · **Language:** KQL · **Hunts:** 24 across 12 ATT&CK tactics

This repository documents *how* I run structured, repeatable threat hunts in the Microsoft security stack — the methodology, the hypothesis framework, the KQL techniques, and a growing library of ready-to-run **Hunt Cards** mapped to MITRE ATT&CK. It is not a dump of queries; it is a hunting *process* you can adopt, with worked examples.

---

## If you are... Start here

| If you are... | Start here |
|---|---|
| **A threat hunter** wanting the process | → [`methodology/00-hunt-process.md`](methodology/00-hunt-process.md) |
| **A SOC analyst** wanting ready hunts | → [`hunts/`](hunts/) — pick a tactic, copy the KQL |
| **A detection engineer** evaluating rigor | → [`methodology/03-triage-and-documentation.md`](methodology/03-triage-and-documentation.md) (graduation criteria) |
| **A red/purple teamer** validating detections | → each Hunt Card's "Malicious confirmation" + [`mapping/attack-coverage.md`](mapping/attack-coverage.md) |
| **A recruiter / hiring manager** | → this README + the methodology docs (process, not just queries) |
| **A student** learning KQL hunting | → [`methodology/02-kql-hunting-techniques.md`](methodology/02-kql-hunting-techniques.md) |

---

## What this is

Threat hunting is **hypothesis-driven, assume-breach** analysis: I don't wait for
an alert — I assume an adversary is already inside and go looking for the evidence
they left. This repo captures that discipline as a six-phase loop (Trigger →
Hypothesis → Scope → Hunt → Triage → Outcome) and applies it to concrete hunts in
Microsoft Sentinel and Defender XDR.

Every hunt is a **Hunt Card**: trigger, falsifiable hypothesis, ATT&CK mapping,
data sources, working KQL, pivot queries, triage guidance, and outcome.

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/rizko-d/threat-hunting-sentinel-defender.git
cd threat-hunting-sentinel-defender

# 2. Read the process
open methodology/00-hunt-process.md

# 3. Run a hunt
#    Copy any .kql block from a Hunt Card into:
#    - Sentinel: Log Analytics → Logs
#    - Defender XDR: security.microsoft.com → Advanced Hunting
#    Swap table names to match what your workspace ingests.
```

No install, no dependencies — the deliverable is knowledge + copy-paste KQL.

---

## Methodology

The heart of the repo. Read these in order:

| Doc | What it covers |
|---|---|
| [00 — Hunt Process](methodology/00-hunt-process.md) | The six-phase loop; Sentinel vs Defender XDR |
| [01 — Hypothesis Framework](methodology/01-hypothesis-framework.md) | Writing specific, falsifiable hypotheses; prioritization scoring |
| [02 — KQL Hunting Techniques](methodology/02-kql-hunting-techniques.md) | Long-tail analysis, joins, beaconing, obfuscation, performance |
| [03 — Triage & Documentation](methodology/03-triage-and-documentation.md) | Verdicts, pivots, evidence standard, hunt→detection graduation |
| [04 — Hunt Chaining (Kill-Chain)](methodology/04-hunt-chaining-killchain.md) | Correlated intrusion stories; how hunts chain into one investigation |

Supporting reference: [Data Sources](docs/data-sources.md) — the Sentinel tables
and Defender XDR schemas I hunt in, plus key Windows event IDs.

---

## Hunt library

Twenty-four Hunt Cards across twelve ATT&CK tactics. Each is a complete, documented,
copy-paste-ready hunt.

| Hunt | ATT&CK | Tactic | Platform |
|---|---|---|---|
| [Phishing Delivery via Mail](hunts/initial-access/phishing-delivery-mail.md) | T1566.001/002 | Initial Access | Defender XDR |
| [Public-Facing App Exploit & Web Shell](hunts/initial-access/public-facing-app-exploit-webshell.md) | T1190/T1505.003 | Initial Access | Both |
| [Malicious User Execution](hunts/initial-access/malicious-user-execution.md) | T1204.001/002 | Initial Access | Defender XDR |
| [Kerberoasting via Anomalous TGS](hunts/credential-access/kerberoasting-anomalous-tgs.md) | T1558.003 | Credential Access | Sentinel + DfI |
| [LSASS Credential Dumping](hunts/credential-access/lsass-credential-dumping.md) | T1003.001 | Credential Access | Defender XDR |
| [Obfuscated PowerShell](hunts/execution/obfuscated-powershell.md) | T1059.001 | Execution | Both |
| [Suspicious Scheduled Task](hunts/persistence/suspicious-scheduled-task.md) | T1053.005 | Persistence | Both |
| [Event Log Clearing](hunts/defense-evasion/event-log-clearing.md) | T1070.001 | Defense Evasion | Both |
| [AD Reconnaissance (BloodHound-style)](hunts/discovery/ad-reconnaissance.md) | T1087/T1069/T1482 | Discovery | Defender for Identity |
| [WMI Lateral Movement](hunts/lateral-movement/wmi-lateral-movement.md) | T1047 | Lateral Movement | Defender XDR |
| [C2 Beaconing by Regularity](hunts/command-and-control/c2-beaconing-regularity.md) | T1071.001 | Command & Control | Both |
| [OAuth Consent & Mailbox Exfil](hunts/exfiltration/oauth-consent-mailbox-exfil.md) | T1098.003/T1114 | Collection/Exfil (cloud) | Both |
| [Screen Capture & Clipboard](hunts/collection/screen-capture-clipboard.md) | T1113/T1115 | Collection | Defender XDR |
| [Archive for Staging](hunts/collection/archive-for-staging.md) | T1560.001 | Collection | Both |
| [Automated Collection from Shares](hunts/collection/automated-collection-file-share.md) | T1119/T1039 | Collection | Defender XDR |
| [Exfiltration Over C2 Channel](hunts/exfiltration/exfil-over-web-c2-channel.md) | T1041 | Exfiltration | Defender XDR |
| [Exfiltration to Cloud Storage](hunts/exfiltration/exfil-to-cloud-storage.md) | T1567.002 | Exfiltration | Both |
| [Exfil Over Alternative Protocol (DNS)](hunts/exfiltration/exfil-over-alternative-protocol-dns.md) | T1048/T1048.003 | Exfiltration | Both |
| [Shadow Copy Deletion](hunts/impact/shadow-copy-deletion.md) | T1490 | Impact | Both |
| [Mass File Encryption](hunts/impact/mass-file-encryption.md) | T1486 | Impact | Defender XDR |
| [Service Stop & Recovery Tamper](hunts/impact/service-stop-recovery-tamper.md) | T1489/T1490 | Impact | Both |
| [UAC Bypass via Auto-Elevate Hijack](hunts/privilege-escalation/uac-bypass-autoelevate.md) | T1548.002 | Privilege Escalation | Both |
| [Token Manipulation & PPID Spoofing](hunts/privilege-escalation/token-manipulation-ppid-spoof.md) | T1134 | Privilege Escalation | Defender XDR |
| [DLL Search-Order Hijacking](hunts/privilege-escalation/dll-search-order-hijacking.md) | T1574.001/002 | Privilege Escalation | Defender XDR |

See [ATTACK_MATRIX.md](ATTACK_MATRIX.md) for the coverage heatmap and
[mapping/attack-coverage.md](mapping/attack-coverage.md) for gap analysis.

---

## Deploy to Sentinel

These hunts aren't just copy-paste — the [`deploy/`](deploy/) directory ships
infrastructure-as-code to push them into Microsoft Sentinel:

```powershell
# Deploy every hunt in a tactic as saved Hunting Queries
./deploy/Deploy-Hunts.ps1 -ResourceGroup rg-sentinel -WorkspaceName law-sentinel `
  -HuntCardPath hunts/credential-access -Mode HuntingQuery

# Promote a validated hunt to a Scheduled Analytic Rule (alerting)
./deploy/Deploy-Hunts.ps1 -ResourceGroup rg-sentinel -WorkspaceName law-sentinel `
  -HuntCardPath hunts/impact/shadow-copy-deletion.md -Mode ScheduledRule
```

`Deploy-Hunts.ps1` parses each Hunt Card's primary KQL + ATT&CK metadata and
deploys via the ARM templates. See [deploy/README.md](deploy/README.md).

## Project structure

```
threat-hunting-sentinel-defender/
├── README.md
├── ATTACK_MATRIX.md              # MITRE coverage heatmap
├── CHANGELOG.md
├── LICENSE                        # MIT
├── methodology/                  # The "how" — the hunting process
│   ├── 00-hunt-process.md
│   ├── 01-hypothesis-framework.md
│   ├── 02-kql-hunting-techniques.md
│   └── 03-triage-and-documentation.md
├── docs/
│   ├── data-sources.md           # Tables/schemas/event IDs reference
│   └── index.md                  # GitHub Pages landing page
├── hunts/                        # Hunt Cards by ATT&CK tactic
│   ├── initial-access/
│   ├── credential-access/
│   ├── execution/
│   ├── persistence/
│   ├── privilege-escalation/
│   ├── defense-evasion/
│   ├── discovery/
│   ├── lateral-movement/
│   ├── collection/
│   ├── command-and-control/
│   ├── exfiltration/
│   └── impact/
├── deploy/                       # Push hunts to Sentinel (ARM + PowerShell)
│   ├── Deploy-Hunts.ps1
│   ├── scheduled-query-rule.template.json
│   └── hunting-query.template.json
├── templates/
│   └── hunt-card.md              # Copy-paste template for new hunts
└── mapping/
    ├── attack-coverage.md        # Coverage tracking + gap analysis
    └── mitre-attack.yaml         # Machine-readable hunt→ATT&CK mapping
```

---

## Sentinel vs Defender XDR

| | Microsoft Sentinel | Defender XDR (Advanced Hunting) |
|---|---|---|
| **Scope** | Whole estate: identity, cloud, network, custom | Endpoints, email, identity, cloud apps |
| **Query surface** | Log Analytics — all ingested tables | Fixed XDR schema (`Device*`, `Email*`, `Identity*`, `Cloud*`) |
| **Retention** | Configurable (up to years) | ~30 days hot |
| **Best for** | Cross-source correlation, long-window APT hunts | Deep endpoint/email detail, near-real-time |

Many hunts run in **both** — find the endpoint behavior in Defender XDR, then
correlate identity/network in Sentinel.

---

## Roadmap

- [x] Six-phase hunting methodology documented
- [x] Hypothesis framework + prioritization scoring
- [x] KQL hunting techniques reference
- [x] Triage & hunt→detection graduation criteria
- [x] Data-sources reference (Sentinel tables + XDR schema + event IDs)
- [x] 9 Hunt Cards across 7 ATT&CK tactics
- [x] ATT&CK coverage tracking + gap analysis
- [x] Impact hunts (ransomware: shadow copy deletion, mass encryption, service stop)
- [x] Privilege Escalation hunts (UAC bypass, token manipulation, DLL hijacking)
- [x] Initial Access hunts (phishing delivery, public-facing app exploit, user execution)
- [x] Collection + Exfiltration hunts (screen/clipboard, archive, C2/cloud/DNS exfil)
- [x] Purple-team validation notes on every Hunt Card
- [x] Kill-chain hunt-chaining playbook (correlated intrusion stories)
- [x] Sentinel deployment tooling (ARM templates + PowerShell)
- [x] GitHub Actions CI (hunt validator + link check)

---

## Author

**Rizko Febri Rachmayadi** — Red + Blue security engineering (pentest, detection
engineering, threat hunting).

## License

MIT — see [LICENSE](LICENSE). Free to use, adapt, and deploy in your own SOC.
