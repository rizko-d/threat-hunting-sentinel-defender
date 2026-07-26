# How I Do Threat Hunting in Microsoft Sentinel & Defender XDR

**A hypothesis-driven threat hunting methodology and KQL hunt library for Microsoft Sentinel and Microsoft Defender XDR (Advanced Hunting).**

> **License:** MIT · **Platform:** Microsoft Sentinel + Defender XDR · **Language:** KQL · **Hunts:** 12 across 8 ATT&CK tactics

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

Supporting reference: [Data Sources](docs/data-sources.md) — the Sentinel tables
and Defender XDR schemas I hunt in, plus key Windows event IDs.

---

## Hunt library

Twelve Hunt Cards across eight ATT&CK tactics. Each is a complete, documented,
copy-paste-ready hunt.

| Hunt | ATT&CK | Tactic | Platform |
|---|---|---|---|
| [Kerberoasting via Anomalous TGS](hunts/credential-access/kerberoasting-anomalous-tgs.md) | T1558.003 | Credential Access | Sentinel + DfI |
| [LSASS Credential Dumping](hunts/credential-access/lsass-credential-dumping.md) | T1003.001 | Credential Access | Defender XDR |
| [Obfuscated PowerShell](hunts/execution/obfuscated-powershell.md) | T1059.001 | Execution | Both |
| [Suspicious Scheduled Task](hunts/persistence/suspicious-scheduled-task.md) | T1053.005 | Persistence | Both |
| [Event Log Clearing](hunts/defense-evasion/event-log-clearing.md) | T1070.001 | Defense Evasion | Both |
| [AD Reconnaissance (BloodHound-style)](hunts/discovery/ad-reconnaissance.md) | T1087/T1069/T1482 | Discovery | Defender for Identity |
| [WMI Lateral Movement](hunts/lateral-movement/wmi-lateral-movement.md) | T1047 | Lateral Movement | Defender XDR |
| [C2 Beaconing by Regularity](hunts/command-and-control/c2-beaconing-regularity.md) | T1071.001 | Command & Control | Both |
| [OAuth Consent & Mailbox Exfil](hunts/exfiltration/oauth-consent-mailbox-exfil.md) | T1098.003/T1114 | Collection/Exfil (cloud) | Both |
| [Shadow Copy Deletion](hunts/impact/shadow-copy-deletion.md) | T1490 | Impact | Both |
| [Mass File Encryption](hunts/impact/mass-file-encryption.md) | T1486 | Impact | Defender XDR |
| [Service Stop & Recovery Tamper](hunts/impact/service-stop-recovery-tamper.md) | T1489/T1490 | Impact | Both |

See [ATTACK_MATRIX.md](ATTACK_MATRIX.md) for the coverage heatmap and
[mapping/attack-coverage.md](mapping/attack-coverage.md) for gap analysis.

---

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
│   ├── credential-access/
│   ├── execution/
│   ├── persistence/
│   ├── defense-evasion/
│   ├── discovery/
│   ├── lateral-movement/
│   ├── command-and-control/
│   ├── exfiltration/
│   └── impact/
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
- [ ] Initial Access hunts (phishing delivery, public-facing app exploit)
- [ ] Privilege Escalation hunts (token manipulation, UAC bypass)
- [ ] Purple-team validation notes per hunt

---

## Author

**Rizko Febri Rachmayadi** — Red + Blue security engineering (pentest, detection
engineering, threat hunting).

## License

MIT — see [LICENSE](LICENSE). Free to use, adapt, and deploy in your own SOC.
