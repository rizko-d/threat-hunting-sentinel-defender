# Hunt Card — Encoded / Obfuscated PowerShell Execution

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-EX-001 |
| **ATT&CK Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Tactic** | Execution |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceProcessEvents`, `SecurityEvent` (4688) |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | Medium–High |

---

## 1. Trigger

Encoded PowerShell is the workhorse of loaders, droppers, and hands-on-keyboard
operators. Scheduled weekly hunt; also triggered by any phishing/initial-access
lead.

## 2. Hypothesis

> **If** an adversary runs obfuscated PowerShell **in order to** execute a payload
> while evading string-based detection, **then** I would observe `powershell.exe`
> invoked with encoded/hidden/download-and-execute flags and abnormally long
> command lines **in** `DeviceProcessEvents`, **distinguishable from normal by**
> the combination of `-enc`/`-w hidden`/`IEX`/`FromBase64String` and command-line
> length far above the admin-script baseline.

**Negative result looks like:** No PowerShell process with encoded-execution flags
and command-line length >300 chars from a non-admin/non-automation context in the
7-day window.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all endpoints; pay special attention to workstations
  spawning PowerShell from Office apps.
- **Known-good baseline:** legitimate management (SCCM, Intune, RMM, deployment
  scripts) uses encoded commands. Baseline by initiating process and signer.

## 4. Hunt Query

```kql
// Obfuscated PowerShell: encoded/hidden execution with long command lines.
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-enc", "-EncodedCommand", "-e ", "FromBase64String",
    "-w hidden", "-windowstyle hidden", "IEX", "Invoke-Expression",
    "DownloadString", "DownloadData", "Net.WebClient", "-nop", "-noprofile"
  )
| extend CmdLen = strlen(ProcessCommandLine)
| extend SuspicionScore =
      toint(ProcessCommandLine has_any ("-enc","-EncodedCommand"))
    + toint(ProcessCommandLine has_any ("-w hidden","-windowstyle hidden"))
    + toint(ProcessCommandLine has_any ("IEX","Invoke-Expression"))
    + toint(ProcessCommandLine has_any ("DownloadString","DownloadData","Net.WebClient"))
    + toint(CmdLen > 300)
| where SuspicionScore >= 2
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          ProcessCommandLine, CmdLen, SuspicionScore, SHA256
| order by SuspicionScore desc, CmdLen desc
```

**Pivots / follow-up queries:**

```kql
// Pivot: PowerShell spawned by an Office app = high-confidence phishing execution.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** initiating process is a known management agent; the
  script is signed/internal; the account is an automation/service identity with a
  documented deployment window.
- **Suspicious indicators:** Office app or `explorer.exe` as parent, `-enc` with
  hidden window, remote download-and-execute, high `SuspicionScore`.
- **Malicious confirmation:** decoding the base64 reveals a loader/stager, the
  host then beacons out, or additional tooling is dropped.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (Script Block Logging 4104 enabled?)
- [ ] Documented clear

**Notes:** For the deepest signal, correlate with PowerShell Script Block Logging
(Event ID 4104) if ingested — it captures the *deobfuscated* script body, not
just the launch command line.

---

## References

- https://attack.mitre.org/techniques/T1059/001/
