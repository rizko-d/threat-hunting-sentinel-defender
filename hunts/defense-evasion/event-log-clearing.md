# Hunt Card — Windows Event Log Clearing

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-DE-001 |
| **ATT&CK Technique** | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| **Tactic** | Defense Evasion |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `SecurityEvent` (1102), `DeviceProcessEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

Log clearing is a strong anti-forensics signal — legitimate admins rarely wipe
security logs. Scheduled hunt and a standard step in any IR triage.

## 2. Hypothesis

> **If** an adversary clears event logs **in order to** destroy evidence, **then**
> I would observe Event ID 1102 (audit log cleared) or `wevtutil cl` / PowerShell
> `Clear-EventLog` execution **in** `SecurityEvent`/`DeviceProcessEvents`,
> **distinguishable from normal by** the near-total absence of legitimate reasons
> to clear the Security log outside of documented maintenance.

**Negative result looks like:** No 1102 events and no `wevtutil cl`/`Clear-EventLog`
executions outside approved maintenance windows in the scope.

## 3. Scope

- **Time window:** last 30 days
- **Environment scope:** all endpoints and servers; DCs are highest priority.
- **Known-good baseline:** rare, documented maintenance/imaging. Any clear should
  map to a change ticket.

## 4. Hunt Query

```kql
// Log clearing via 1102 (Sentinel) — the authoritative signal.
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 1102               // The audit log was cleared
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, Activity
| order by TimeGenerated desc
```

**Pivots / follow-up queries:**

```kql
// Endpoint route: log-clearing tooling execution.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl ", "clear-log"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Clear-EventLog","Remove-EventLog","Clear-WinEvent"))
    or ProcessCommandLine has "Clear-EventLog"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** documented maintenance/imaging with a change ticket and
  a known admin performing it.
- **Suspicious indicators:** clear on a DC or crown-jewel server, clear performed
  by an unusual account, clear immediately following other suspicious activity.
- **Malicious confirmation:** clearing is bracketed by other attack behavior
  (dumping, lateral movement) — a deliberate evidence wipe mid-intrusion.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (are logs forwarded off-host to survive local clears?)
- [ ] Documented clear

**Notes:** The best defense against this technique is **log forwarding** — if
`SecurityEvent` is shipped to Sentinel in real time, a local clear doesn't destroy
the evidence, and the 1102 itself becomes the alert. A hunt hit where forwarding
was *not* configured is a visibility-gap finding.

---

## References

- https://attack.mitre.org/techniques/T1070/001/
- Windows Security Event ID 1102 (audit log cleared)
