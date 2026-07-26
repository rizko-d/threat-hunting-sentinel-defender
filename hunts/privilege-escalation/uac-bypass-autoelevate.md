# Hunt Card — UAC Bypass via Auto-Elevated Binary Hijack

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-PR-001 |
| **ATT&CK Technique** | T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC |
| **Tactic** | Privilege Escalation / Defense Evasion |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceProcessEvents`, `DeviceRegistryEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

UAC bypass is the standard way commodity and hands-on-keyboard attackers jump
from medium to high integrity without a credential prompt. The classic
auto-elevate hijacks (fodhelper, eventvwr, sdclt, computerdefaults) leave a very
specific registry + process signature. Scheduled hunt; also triggered by any
post-exploitation lead where the attacker needs local admin.

## 2. Hypothesis

> **If** an adversary bypasses UAC **in order to** obtain a high-integrity process
> without prompting, **then** I would observe a known auto-elevating Windows binary
> (`fodhelper.exe`, `eventvwr.exe`, `sdclt.exe`, `computerdefaults.exe`) spawning
> an unexpected child (cmd/powershell/attacker binary), often preceded by a write
> to the hijacked registry key (e.g. `HKCU\...\ms-settings\shell\open\command`),
> **in** `DeviceProcessEvents`/`DeviceRegistryEvents`, **distinguishable from
> normal by** the auto-elevate binary parenting a shell it would never normally
> launch.

**Negative result looks like:** No auto-elevating binary spawned a shell/LOLBin
child, and no writes to the known UAC-bypass hijack registry keys, across the
estate in the window.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all endpoints; workstations highest priority (where users
  run as local admin with UAC).
- **Known-good baseline:** these binaries normally launch settings/MMC UIs, not
  command shells. A shell child is the anomaly by definition.

## 4. Hunt Query

```kql
// UAC bypass: auto-elevating binary spawning a shell/LOLBin child.
let lookback = 7d;
let autoelevate = dynamic([
    "fodhelper.exe","eventvwr.exe","sdclt.exe","computerdefaults.exe",
    "slui.exe","wsreset.exe","dccw.exe","fltMC.exe","cmstp.exe"
]);
let suspicious_children = dynamic([
    "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
    "mshta.exe","rundll32.exe","regsvr32.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ (autoelevate)
| where FileName in~ (suspicious_children)
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Registry route: writes to the ms-settings / mscfile hijack keys (fodhelper/eventvwr).
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any (
    @"\Classes\ms-settings\shell\open\command",
    @"\Classes\mscfile\shell\open\command",
    @"\Classes\exefile\shell\runas\command",
    @"\Classes\Folder\shell\open\command"
  )
| where InitiatingProcessFileName !in~ ("svchost.exe","explorer.exe")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** none typical — auto-elevate binaries launching command
  shells is inherently abnormal. A rare admin script might, but it should be
  identifiable and justified.
- **Suspicious indicators:** `fodhelper.exe → powershell.exe`, a `DelegateExecute`
  or `ms-settings\shell\open\command` write from a user process, an encoded child
  command line.
- **Malicious confirmation:** the child runs at high integrity, followed by
  credential access, persistence, or defense-tampering that requires admin.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1548.002` (fodhelper, eventvwr, sdclt bypass)
- **Expected hit:** the auto-elevate binary parents a shell child, and/or the ms-settings/mscfile registry-key write appears.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (registry auditing enabled? UAC set to always-notify?)
- [ ] Documented clear

**Notes:** Two detection surfaces, use both — the registry write is the *setup*,
the process spawn is the *payoff*. Catching the registry write is earlier and even
higher-confidence. UACMe implements 70+ variants; the parent→shell relationship
generalizes across most of them better than key-specific rules.

---

## References

- https://attack.mitre.org/techniques/T1548/002/
- UACMe (hfiref0x) — catalog of UAC bypass methods
