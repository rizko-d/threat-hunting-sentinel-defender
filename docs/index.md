---
title: Threat Hunting in Microsoft Sentinel & Defender XDR
description: A hypothesis-driven threat hunting methodology and KQL hunt library for Microsoft Sentinel and Microsoft Defender XDR (Advanced Hunting). MITRE ATT&CK mapped Hunt Cards for SOC analysts and threat hunters.
---

# Threat Hunting in Microsoft Sentinel & Microsoft Defender XDR

A **hypothesis-driven threat hunting methodology** and **KQL hunt library** for
the Microsoft security stack — Microsoft Sentinel and Microsoft Defender XDR
(Advanced Hunting). Every hunt is a documented, MITRE ATT&CK-mapped **Hunt Card**
with working KQL you can copy straight into your workspace.

Keywords: threat hunting, Microsoft Sentinel, Microsoft Defender XDR, KQL,
Kusto Query Language, Advanced Hunting, MITRE ATT&CK, SOC, detection engineering,
threat detection, Kerberoasting, LSASS dumping, C2 beaconing, lateral movement,
hunt methodology, blue team.

## What's inside

- **A repeatable hunting process** — the six-phase loop: Trigger → Hypothesis →
  Scope → Hunt → Triage → Outcome.
- **A hypothesis framework** — how to write specific, falsifiable hunting
  hypotheses and prioritize what to hunt first.
- **KQL hunting techniques** — long-tail analysis, joins, beaconing detection,
  obfuscation hunting, and performance patterns for Sentinel + Defender XDR.
- **9 Hunt Cards** across 7 ATT&CK tactics, each with working KQL, pivot queries,
  triage guidance, and outcomes.

## Hunt library (MITRE ATT&CK mapped)

| Hunt | ATT&CK | Tactic |
|---|---|---|
| Kerberoasting via Anomalous TGS | T1558.003 | Credential Access |
| LSASS Credential Dumping | T1003.001 | Credential Access |
| Obfuscated PowerShell | T1059.001 | Execution |
| Suspicious Scheduled Task | T1053.005 | Persistence |
| Event Log Clearing | T1070.001 | Defense Evasion |
| AD Reconnaissance | T1087/T1069/T1482 | Discovery |
| WMI Lateral Movement | T1047 | Lateral Movement |
| C2 Beaconing by Regularity | T1071.001 | Command & Control |
| OAuth Consent & Mailbox Exfil | T1098.003/T1114 | Collection/Exfiltration |
| Shadow Copy Deletion | T1490 | Impact |
| Mass File Encryption | T1486 | Impact |
| Service Stop & Recovery Tamper | T1489/T1490 | Impact |
| UAC Bypass via Auto-Elevate Hijack | T1548.002 | Privilege Escalation |
| Token Manipulation & PPID Spoofing | T1134 | Privilege Escalation |
| DLL Search-Order Hijacking | T1574.001/002 | Privilege Escalation |

## Who this is for

- **SOC analysts** who need ready-to-run KQL hunts for Sentinel and Defender XDR.
- **Threat hunters** adopting a structured, hypothesis-driven methodology.
- **Detection engineers** looking for the hunt→detection graduation path.
- **Purple teams** validating detection coverage against real adversary TTPs.

## Get started

Browse the full repository on
[GitHub](https://github.com/rizko-d/threat-hunting-sentinel-defender). Start with
the [hunting methodology](https://github.com/rizko-d/threat-hunting-sentinel-defender/blob/main/methodology/00-hunt-process.md),
then pick a Hunt Card and run it.

---

Authored by **Rizko Febri Rachmayadi** · MIT License
