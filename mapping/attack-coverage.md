# ATT&CK Coverage Tracking

How this hunt library maps onto MITRE ATT&CK, and where the current gaps are.
Coverage tracking turns ad-hoc hunting into a *program* — over time it shows
which tactics are well-covered and which are blind spots to prioritize next.

---

## Coverage philosophy

I don't chase 100% ATT&CK coverage — that's a vanity metric. I prioritize the
techniques that are (a) most used against my sector/stack, (b) highest impact if
successful, and (c) actually observable with the telemetry I have. A deliberately
covered 30% beats a checkbox 100%.

---

## Current coverage

| Tactic | Techniques Hunted | Hunt Cards |
|---|---|---|
| Initial Access | T1566.001/002, T1190, T1505.003, T1204.001/002 | Phishing Delivery, Public-Facing App Exploit & Web Shell, Malicious User Execution |
| Credential Access | T1558.003, T1003.001 | Kerberoasting, LSASS Dumping |
| Execution | T1059.001 | Obfuscated PowerShell |
| Privilege Escalation | T1548.002, T1134, T1574.001/002 | UAC Bypass, Token Manipulation & PPID Spoofing, DLL Search-Order Hijacking |
| Persistence | T1053.005 | Scheduled Task |
| Defense Evasion | T1070.001 | Event Log Clearing |
| Discovery | T1087, T1069, T1482 | AD Reconnaissance |
| Lateral Movement | T1047 | WMI Lateral Movement |
| Command and Control | T1071.001 | C2 Beaconing |
| Collection | T1113, T1115, T1560.001, T1119, T1039 | Screen Capture & Clipboard, Archive for Staging, Automated Collection from Shares |
| Exfiltration | T1041, T1567.002, T1048/.003, T1098.003, T1114 | Exfil Over C2, Exfil to Cloud Storage, Exfil Over Alt Protocol (DNS), OAuth Consent & Mailbox Exfil |
| Impact | T1490, T1486, T1489 | Shadow Copy Deletion, Mass File Encryption, Service Stop & Recovery Tamper |

**Tactics with hunts:** 12 of 14
**Techniques hunted:** 30+

---

## Gap analysis (roadmap targets)

Tactics not yet covered, prioritized for future hunt cards:

| Tactic | Priority | Candidate hunts |
|---|---|---|
| Resource Development | Low | (mostly pre-intrusion, limited internal telemetry) |
| Reconnaissance | Low | (external; limited internal telemetry) |

---

## How coverage feeds the hunt program

1. **Monthly review** — walk the matrix, pick the highest-priority uncovered
   technique that's relevant + observable.
2. **Purple-team alignment** — when the red team runs a TTP, confirm there's a
   hunt card (or write one) and validate it fires.
3. **Promote-and-retire** — hunts that graduate to detections move out of
   "active hunt" into the SIEM's analytic rules; the coverage note records that
   the technique is now *continuously* monitored, not just point-in-time hunted.

See [../mapping/mitre-attack.yaml](mitre-attack.yaml) for the machine-readable
mapping.
