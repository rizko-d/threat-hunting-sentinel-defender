# Data Sources Reference

The tables I hunt in, split by platform. Pick the table that holds your
observable, and swap names to match what your workspace actually ingests.

---

## Microsoft Defender XDR — Advanced Hunting schema

Stable, well-documented schema. ~30 days of hot data. Query at
`security.microsoft.com` → Advanced Hunting, or via the streamed tables in
Sentinel if the M365 Defender connector is enabled.

### Endpoint (Defender for Endpoint)

| Table | Holds | Common hunt use |
|---|---|---|
| `DeviceProcessEvents` | Process creation | Parent/child anomalies, LOLBins, encoded PS |
| `DeviceNetworkEvents` | Network connections | Beaconing, rare destinations, exfil |
| `DeviceFileEvents` | File create/modify/delete | Webshells, dropped tooling, ransomware writes |
| `DeviceRegistryEvents` | Registry changes | Run keys, service installs, tamper |
| `DeviceLogonEvents` | Logons on the device | Lateral movement, pass-the-hash patterns |
| `DeviceImageLoadEvents` | DLL loads | Sideloading, unsigned module loads |
| `DeviceEvents` | Misc sensor events | AV detections, AMSI, WMI, named pipes |
| `DeviceInfo` | Device inventory | Scope, OS, join type |
| `DeviceTvmSoftwareVulnerabilities` | TVM vuln inventory | Patch cross-check for a CVE |

### Identity (Defender for Identity)

| Table | Holds | Common hunt use |
|---|---|---|
| `IdentityLogonEvents` | AD/Azure AD logons | Kerberoasting, PtT, anomalous logons |
| `IdentityQueryEvents` | AD queries (LDAP, SAMR, DNS) | Recon / enumeration (BloodHound-style) |
| `IdentityDirectoryEvents` | Directory changes | Account manipulation, group changes |

### Email & apps (Defender for Office 365 / Cloud Apps)

| Table | Holds | Common hunt use |
|---|---|---|
| `EmailEvents` | Mail flow | Phishing delivery, spoofing |
| `EmailAttachmentInfo` | Attachment detail | Malicious attachments |
| `EmailUrlInfo` | URLs in mail | Phishing links |
| `CloudAppEvents` | M365 / SaaS activity | OAuth abuse, mailbox rules, mass download |

### Alerts

| Table | Holds |
|---|---|
| `AlertInfo` | Alert metadata (title, severity, category) |
| `AlertEvidence` | Entities tied to each alert |

---

## Microsoft Sentinel — common Log Analytics tables

Sentinel sees the *whole estate*, not just endpoints. Which tables exist depends
on your connectors. The frequently-hunted ones:

### Identity / Azure AD

| Table | Holds |
|---|---|
| `SigninLogs` | Interactive Azure AD sign-ins |
| `AADNonInteractiveUserSignInLogs` | Non-interactive sign-ins (tokens, service) |
| `AuditLogs` | Azure AD directory changes |
| `AADServicePrincipalSignInLogs` | Service principal sign-ins |

### Windows / on-prem

| Table | Holds |
|---|---|
| `SecurityEvent` | Windows Security event log (4624, 4769, 1102, 4688…) |
| `Event` | Other Windows event channels (Sysmon via WEF) |
| `DeviceProcessEvents` etc. | Defender tables streamed into Sentinel |

### Network / infrastructure

| Table | Holds |
|---|---|
| `CommonSecurityLog` | CEF/Syslog (firewalls, proxies, NDR) |
| `AzureDiagnostics` | Azure resource diagnostics |
| `AzureNetworkAnalytics_CL` | NSG flow logs (Traffic Analytics) |
| `DnsEvents` | DNS query logs |

### Cloud / activity

| Table | Holds |
|---|---|
| `AzureActivity` | Azure control-plane operations |
| `OfficeActivity` | O365 unified audit log |
| `AWSCloudTrail` | AWS API activity (via connector) |

---

## Key event IDs (Windows `SecurityEvent`)

| Event ID | Meaning | Hunt relevance |
|---|---|---|
| 4624 | Successful logon | Logon type analysis, lateral movement |
| 4625 | Failed logon | Brute force, spraying |
| 4688 | Process creation | Command-line hunting (if audit enabled) |
| 4769 | Kerberos service ticket | Kerberoasting (RC4/0x17, SPN volume) |
| 4768 | Kerberos TGT request | AS-REP roasting, ticket anomalies |
| 4672 | Special privileges assigned | Privileged logon tracking |
| 1102 | Security log cleared | Anti-forensics / defense evasion |
| 7045 | Service installed | Persistence, remote exec (PsExec) |
| 5861 | WMI event consumer bound | WMI persistence |

---

## Retention & window strategy

- **Defender XDR Advanced Hunting**: ~30 days. Good for near-real-time and
  recent-dwell hunts.
- **Sentinel**: configurable (typically 90 days interactive, longer via archive
  / basic logs / data lake). Use it for **long-window APT hunts** where dwell
  time may be months.
- Match the **time window to the threat class**: commodity malware = hours/days;
  targeted intrusion = weeks/months.
