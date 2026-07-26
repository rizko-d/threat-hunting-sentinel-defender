# Hunt Card — Suspicious Scheduled Task Persistence

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-PE-001 |
| **ATT&CK Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Tactic** | Persistence |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceProcessEvents`, `SecurityEvent` (4698) |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | Medium–High |

---

## 1. Trigger

Scheduled tasks are a durable, low-friction persistence mechanism favored by
everything from commodity malware to APTs. Scheduled monthly hunt; also triggered
after any endpoint compromise to check for planted persistence.

## 2. Hypothesis

> **If** an adversary creates a scheduled task **in order to** persist or execute
> on a trigger, **then** I would observe `schtasks.exe /create` (or 4698 task
> registration) referencing a suspicious binary/path or encoded command **in**
> `DeviceProcessEvents`/`SecurityEvent`, **distinguishable from normal by** the
> task action pointing at temp/user-writable paths, LOLBins, or encoded scripts,
> and the task name being random or masquerading.

**Negative result looks like:** No scheduled task created in the window whose
action references a user-writable/temp path, an encoded command, or a
non-allowlisted binary.

## 3. Scope

- **Time window:** last 30 days
- **Environment scope:** all endpoints
- **Known-good baseline:** software installers, Windows Update, and management
  agents create tasks. Baseline expected task names and initiating processes.

## 4. Hunt Query

```kql
// Suspicious scheduled task creation via schtasks or process telemetry.
let lookback = 30d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| extend LowerCmd = tolower(ProcessCommandLine)
| where LowerCmd has_any (
    "\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\",
    "powershell", "-enc", "cmd /c", "mshta", "wscript", "cscript",
    "regsvr32", "rundll32", "bitsadmin", "curl", "certutil"
  )
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          ProcessCommandLine, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Sentinel route: Windows task registration event with author + command.
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4698                        // A scheduled task was created
| project TimeGenerated, Computer, SubjectUserName, EventData
| extend TaskContent = tostring(EventData)
| where TaskContent has_any ("powershell","-enc","\\Temp\\","\\AppData\\","mshta","regsvr32","rundll32")
| order by TimeGenerated desc
```

## 5. Triage Guidance

- **Benign indicators:** created by a known installer/management agent; task
  points at a signed binary in Program Files; recognizable vendor task name.
- **Suspicious indicators:** action in `\Temp\`/`\AppData\`, encoded PowerShell,
  LOLBin execution, randomized/masquerading task name, SYSTEM run level from a
  user context.
- **Malicious confirmation:** the referenced payload is malicious, the task
  triggers a beacon, or it re-creates itself after removal.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is 4698 auditing enabled?)
- [ ] Documented clear

**Notes:** Also hunt task *modification* and tasks that run only on rare triggers
(logon of a specific user, idle) — attackers hide in low-visibility triggers.

---

## References

- https://attack.mitre.org/techniques/T1053/005/
- Windows Security Event ID 4698 (scheduled task created)
