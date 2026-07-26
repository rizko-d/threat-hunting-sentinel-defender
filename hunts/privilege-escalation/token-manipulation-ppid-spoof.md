# Hunt Card — Access Token Manipulation & Parent-PID Spoofing

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-PR-002 |
| **ATT&CK Technique** | T1134 — Access Token Manipulation |
| **Tactic** | Privilege Escalation / Defense Evasion |
| **Platform(s)** | Defender XDR |
| **Data Source(s)** | `DeviceProcessEvents`, `DeviceEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

Token theft/impersonation and parent-PID spoofing let an attacker run as SYSTEM or
as another user, and disguise the true process lineage. Cobalt Strike
(`spawnto`/`ppid`), Meterpreter (`steal_token`), and named-pipe impersonation
(PsExec/Print Spooler abuse) all rely on it. Scheduled hunt; triggered by any
privilege-escalation lead.

## 2. Hypothesis

> **If** an adversary manipulates access tokens or spoofs a parent process **in
> order to** escalate to SYSTEM/another user or hide lineage, **then** I would
> observe a process whose declared parent is implausible for its behavior (e.g. a
> user shell parented to a system service it never legitimately spawns from), or a
> process running at SYSTEM integrity spawned from a user-context chain, **in**
> `DeviceProcessEvents`, **distinguishable from normal by** the mismatch between
> declared parentage/integrity and the actual initiating context.

**Negative result looks like:** No process exhibited a parent/integrity mismatch
(user-context grandparent → SYSTEM child via an implausible spoofed parent) across
the estate in the window, and no named-pipe-impersonation execution pattern
appeared.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all endpoints; servers/jump hosts highest priority.
- **Known-good baseline:** legitimate service managers (`services.exe`, `svchost`)
  spawn SYSTEM children constantly. Baseline the *normal* SYSTEM-spawn parents so
  the anomalies stand out.

## 4. Hunt Query

```kql
// Parent-PID spoofing / token abuse: implausible SYSTEM child from a user chain.
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe")
// Declared parent is a system-ish process, but the grandparent/initiating chain is user-context
| where InitiatingProcessParentFileName in~ ("services.exe","wininit.exe","lsass.exe","spoolsv.exe","svchost.exe")
| where InitiatingProcessAccountName in~ ("system","local service","network service") 
// but a real user account is present in the account context — mismatch
| where AccountName !in~ ("system","local service","network service") and isnotempty(AccountName)
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, ProcessIntegrityLevel, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Named-pipe impersonation (PrintSpoofer / RoguePotato / PsExec) — SYSTEM shell via pipe.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessIntegrityLevel == "System" or ProcessTokenElevation == "TokenElevationTypeFull"
| where InitiatingProcessCommandLine has_any (@"\\.\pipe\", "PrintSpoofer", "RoguePotato", "JuicyPotato", "PSEXESVC")
    or ProcessCommandLine has @"\\.\pipe\"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine, ProcessIntegrityLevel
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** legitimate service/scheduled-task execution running as
  SYSTEM with a recognized parent; management agents that impersonate for
  deployment with a documented purpose.
- **Suspicious indicators:** a user-context command shell suddenly at SYSTEM
  integrity, an implausible declared parent (spoolsv → powershell), named-pipe
  impersonation tooling, `SeDebugPrivilege`/`SeImpersonatePrivilege` use by a
  non-service process.
- **Malicious confirmation:** the escalated process performs admin-only actions
  (LSASS access, service install, defense tampering) it could not do pre-escalation.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is integrity-level / token telemetry populated?)
- [ ] Documented clear

**Notes:** Field availability varies — `ProcessIntegrityLevel`,
`ProcessTokenElevation`, and `InitiatingProcessParentFileName` are the key
discriminators; if any are sparse in your tenant, lean on the named-pipe pivot,
which is more universally logged. Correlate with TH-CA-002 (LSASS) — token theft
often follows a credential-access step.

---

## References

- https://attack.mitre.org/techniques/T1134/
- SeImpersonate "Potato" family (PrintSpoofer, RoguePotato, JuicyPotato)
