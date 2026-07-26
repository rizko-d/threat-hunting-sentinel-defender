# Hunt Card — Malicious Attachment / Link User Execution

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-IA-003 |
| **ATT&CK Technique** | T1204.001 / T1204.002 — User Execution: Malicious Link / File |
| **Tactic** | Initial Access / Execution |
| **Platform(s)** | Defender XDR |
| **Data Source(s)** | `DeviceProcessEvents`, `DeviceFileEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

Delivery (TH-IA-001) only matters if the user *acts*. This hunt catches the
click/open — the moment a lure becomes execution: an Office app or browser
spawning a shell, or a user launching a payload from a downloaded archive/ISO.
It's the bridge between the inbox and the endpoint compromise. Scheduled daily;
triggered by any delivered-phish lead.

## 2. Hypothesis

> **If** a user executes a malicious file or link **in order for** the adversary to
> gain code execution, **then** I would observe an Office application, browser, or
> mail client spawning a script host/shell, or a process launching from a
> download/archive/ISO mount path, **in** `DeviceProcessEvents`, **distinguishable
> from normal by** the productivity/browser app parenting an interpreter it should
> never launch, or execution originating from a `\Downloads\`/mounted-ISO path.

**Negative result looks like:** No Office/browser/mail process spawned a
script host or shell, and no process executed from a downloads/archive/ISO-mount
path, across the estate in the window.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all endpoints; user workstations are the primary surface.
- **Known-good baseline:** some line-of-business Office macros and browser-launched
  helper apps are legitimate. Baseline and allowlist by signer and known template.

## 4. Hunt Query

```kql
// User execution: Office/browser/mail app spawning a script host or shell.
let lookback = 7d;
let lure_parents = dynamic([
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe",
    "msaccess.exe","mspub.exe","chrome.exe","msedge.exe","firefox.exe",
    "acrord32.exe","acrobat.exe"
]);
let payload_children = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe",
    "mshta.exe","rundll32.exe","regsvr32.exe","curl.exe","certutil.exe","bitsadmin.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ (lure_parents)
| where FileName in~ (payload_children)
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Execution from a downloads / archive / mounted-ISO path (double-click of a lure).
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend Folder = tolower(FolderPath)
| where Folder has_any (@"\downloads\", @"\temp\", @"\appdata\local\temp\", @"\7zip", @"\rar$", @"\winrar")
    or (Folder matches regex @"^[d-z]:\\" and InitiatingProcessFileName in~ ("explorer.exe"))   // launched from a mounted ISO drive letter
| where FileName endswith ".exe" or FileName endswith ".scr" or FileName endswith ".dll"
| where InitiatingProcessFileName in~ ("explorer.exe","7zFM.exe","winrar.exe","OpenWith.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** a signed, known line-of-business macro or a legitimate
  browser-helper launch; execution from Downloads of a recognized, signed installer
  the user intentionally ran.
- **Suspicious indicators:** `winword.exe → powershell -enc`, `outlook.exe → mshta`,
  an unsigned binary run from a mounted ISO or extracted archive, LOLBin download
  utilities parented by an Office app.
- **Malicious confirmation:** the spawned process beacons, drops further tooling,
  or establishes persistence — correlate to TH-EX-001 (obfuscated PowerShell) and
  TH-C2-001 (beaconing), and back to TH-IA-001 (the delivering message).

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** This is the keystone that links the three kill-chain stages —
delivery (TH-IA-001) → user execution (this) → payload/C2 (TH-EX-001, TH-C2-001).
When it fires, always pivot *backward* to the delivering email and *forward* to
the post-execution behavior to scope the full intrusion.

---

## References

- https://attack.mitre.org/techniques/T1204/001/
- https://attack.mitre.org/techniques/T1204/002/
