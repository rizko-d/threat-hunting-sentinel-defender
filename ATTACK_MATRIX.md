# MITRE ATT&CK Coverage Matrix

Coverage heatmap for the threat-hunting library. Each cell shows the Hunt Card(s)
covering that technique.

## Coverage summary

| Metric | Value |
|---|---|
| **Tactics covered** | 10 of 14 |
| **Techniques hunted** | 22+ |
| **Hunt Cards** | 18 |
| **Platforms** | Microsoft Sentinel + Defender XDR |

## Coverage by tactic

### Initial Access

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1566.001 | Spearphishing Attachment | [Phishing Delivery via Mail](hunts/initial-access/phishing-delivery-mail.md) | Defender XDR |
| T1566.002 | Spearphishing Link | [Phishing Delivery via Mail](hunts/initial-access/phishing-delivery-mail.md) | Defender XDR |
| T1190 | Exploit Public-Facing Application | [Public-Facing App Exploit & Web Shell](hunts/initial-access/public-facing-app-exploit-webshell.md) | Both |
| T1505.003 | Web Shell | [Public-Facing App Exploit & Web Shell](hunts/initial-access/public-facing-app-exploit-webshell.md) | Both |
| T1204.001 | Malicious Link | [Malicious User Execution](hunts/initial-access/malicious-user-execution.md) | Defender XDR |
| T1204.002 | Malicious File | [Malicious User Execution](hunts/initial-access/malicious-user-execution.md) | Defender XDR |

### Credential Access

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1558.003 | Kerberoasting | [Kerberoasting via Anomalous TGS](hunts/credential-access/kerberoasting-anomalous-tgs.md) | Sentinel + DfI |
| T1003.001 | LSASS Memory | [LSASS Credential Dumping](hunts/credential-access/lsass-credential-dumping.md) | Defender XDR |

### Execution

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1059.001 | PowerShell | [Obfuscated PowerShell](hunts/execution/obfuscated-powershell.md) | Both |

### Privilege Escalation

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1548.002 | Bypass User Account Control | [UAC Bypass via Auto-Elevate Hijack](hunts/privilege-escalation/uac-bypass-autoelevate.md) | Both |
| T1134 | Access Token Manipulation | [Token Manipulation & PPID Spoofing](hunts/privilege-escalation/token-manipulation-ppid-spoof.md) | Defender XDR |
| T1574.001 | DLL Search Order Hijacking | [DLL Search-Order Hijacking](hunts/privilege-escalation/dll-search-order-hijacking.md) | Defender XDR |
| T1574.002 | DLL Side-Loading | [DLL Search-Order Hijacking](hunts/privilege-escalation/dll-search-order-hijacking.md) | Defender XDR |

### Persistence

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1053.005 | Scheduled Task | [Suspicious Scheduled Task](hunts/persistence/suspicious-scheduled-task.md) | Both |

### Defense Evasion

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1070.001 | Clear Windows Event Logs | [Event Log Clearing](hunts/defense-evasion/event-log-clearing.md) | Both |

### Discovery

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1087 | Account Discovery | [AD Reconnaissance](hunts/discovery/ad-reconnaissance.md) | Defender for Identity |
| T1069 | Permission Groups Discovery | [AD Reconnaissance](hunts/discovery/ad-reconnaissance.md) | Defender for Identity |
| T1482 | Domain Trust Discovery | [AD Reconnaissance](hunts/discovery/ad-reconnaissance.md) | Defender for Identity |

### Lateral Movement

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1047 | Windows Management Instrumentation | [WMI Lateral Movement](hunts/lateral-movement/wmi-lateral-movement.md) | Defender XDR |

### Command and Control

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1071.001 | Web Protocols (Beaconing) | [C2 Beaconing by Regularity](hunts/command-and-control/c2-beaconing-regularity.md) | Both |

### Collection / Exfiltration (cloud)

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1098.003 | Additional Cloud Roles | [OAuth Consent & Mailbox Exfil](hunts/exfiltration/oauth-consent-mailbox-exfil.md) | Both |
| T1114 | Email Collection | [OAuth Consent & Mailbox Exfil](hunts/exfiltration/oauth-consent-mailbox-exfil.md) | Both |

### Impact

| Technique | Name | Hunt Card | Platform |
|---|---|---|---|
| T1490 | Inhibit System Recovery | [Shadow Copy Deletion](hunts/impact/shadow-copy-deletion.md) | Both |
| T1486 | Data Encrypted for Impact | [Mass File Encryption](hunts/impact/mass-file-encryption.md) | Defender XDR |
| T1489 | Service Stop | [Service Stop & Recovery Tamper](hunts/impact/service-stop-recovery-tamper.md) | Both |
| T1490 | Inhibit System Recovery | [Service Stop & Recovery Tamper](hunts/impact/service-stop-recovery-tamper.md) | Both |

## Uncovered tactics (roadmap)

| Tactic | Status | Planned |
|---|---|---|
| Reconnaissance | Out of scope | Limited internal telemetry |
| Resource Development | Out of scope | Pre-intrusion |

See [mapping/attack-coverage.md](mapping/attack-coverage.md) for gap analysis and
prioritization.
