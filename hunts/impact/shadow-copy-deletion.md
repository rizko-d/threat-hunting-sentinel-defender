# Hunt Card — Shadow Copy Deletion (Inhibit Recovery)

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-IM-001 |
| **ATT&CK Technique** | T1490 — Inhibit System Recovery |
| **Tactic** | Impact |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceProcessEvents`, `SecurityEvent` (4688) |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | Critical |

---

## 1. Trigger

Deleting Volume Shadow Copies is the near-universal pre-encryption step in
ransomware — it strips the victim's ability to roll back. Catching it is one of
the highest-value, lowest-false-positive hunts there is. Scheduled daily hunt;
also triggered by any ransomware CTI or an endpoint alert mentioning `vssadmin`.

## 2. Hypothesis

> **If** an adversary deletes shadow copies **in order to** inhibit recovery
> before encrypting, **then** I would observe `vssadmin delete shadows`,
> `wmic shadowcopy delete`, `wbadmin delete`, or `Get-WmiObject Win32_Shadowcopy |
> Remove-WmiObject` execution **in** `DeviceProcessEvents`/`SecurityEvent`,
> **distinguishable from normal by** the near-total absence of legitimate business
> reasons to bulk-delete shadow copies, especially from a non-admin/non-backup
> context.

**Negative result looks like:** No shadow-copy-deletion command executed outside
approved backup/maintenance jobs across the estate in the window.

## 3. Scope

- **Time window:** last 7 days (fast-moving, high-severity class)
- **Environment scope:** all endpoints and servers; file servers and DCs highest
  priority.
- **Known-good baseline:** legitimate backup software and some imaging tools prune
  shadow copies. Baseline by initiating process (backup agent) and account.

## 4. Hunt Query

```kql
// Shadow copy / backup catalog deletion — ransomware pre-encryption behavior.
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend Cmd = tolower(ProcessCommandLine)
| where
    // vssadmin / wmic shadow copy deletion
    (FileName in~ ("vssadmin.exe","wmic.exe") and Cmd has "shadow" and Cmd has_any ("delete","resize"))
    // wbadmin backup catalog deletion
    or (FileName =~ "wbadmin.exe" and Cmd has "delete" and Cmd has_any ("catalog","systemstatebackup","backup"))
    // PowerShell WMI shadow removal
    or (FileName in~ ("powershell.exe","pwsh.exe") and Cmd has "win32_shadowcopy" and Cmd has_any ("remove-wmiobject","delete","remove-ciminstance"))
    // bcdedit recovery tamper (often paired)
    or (FileName =~ "bcdedit.exe" and Cmd has_any ("recoveryenabled no","bootstatuspolicy ignoreallfailures"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Sentinel route via 4688 process creation.
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| extend Cmd = tolower(CommandLine)
| where (Cmd has "vssadmin" and Cmd has "delete" and Cmd has "shadow")
    or (Cmd has "wmic" and Cmd has "shadowcopy" and Cmd has "delete")
    or (Cmd has "wbadmin" and Cmd has "delete")
    or (Cmd has "bcdedit" and Cmd has "recoveryenabled")
| project TimeGenerated, Computer, SubjectUserName, NewProcessName, CommandLine
| order by TimeGenerated desc
```

## 5. Triage Guidance

- **Benign indicators:** the initiating process is a known backup/imaging agent
  running on a documented schedule; the account is a backup service identity.
- **Suspicious indicators:** `vssadmin delete shadows /all /quiet`, deletion by a
  user or non-backup process, `bcdedit` recovery tamper alongside it, execution on
  a workstation that has no backup role.
- **Malicious confirmation:** the deletion is immediately followed by mass file
  modification/encryption, ransom note creation, or service/process termination of
  security tooling.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is command-line auditing / 4688 enabled everywhere?)
- [ ] Documented clear

**Notes:** This is one of the best "single-command" ransomware canaries. If it
fires with `/all /quiet`, treat as active ransomware until proven otherwise —
isolate the host first, ask questions second. Pair this hunt with TH-IM-002 (mass
encryption) which typically follows within minutes.

---

## References

- https://attack.mitre.org/techniques/T1490/
- LOLBAS: vssadmin.exe, wmic.exe, wbadmin.exe, bcdedit.exe
