# Hunt Card — WMI Lateral Movement

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-LM-001 |
| **ATT&CK Technique** | T1047 — Windows Management Instrumentation |
| **Tactic** | Lateral Movement / Execution |
| **Platform(s)** | Defender XDR |
| **Data Source(s)** | `DeviceProcessEvents`, `DeviceLogonEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

WMI (`wmic /node:`, `Win32_Process.Create`, Impacket `wmiexec`) is a favored
fileless lateral-movement channel. Triggered by any confirmed foothold — "the
attacker is on host A; are they pivoting?" — and run on a scheduled cadence.

## 2. Hypothesis

> **If** an adversary moves laterally via WMI **in order to** execute on a remote
> host without dropping tooling, **then** I would observe `wmiprvse.exe` spawning
> a shell/LOLBin on the target shortly after a Type 3 (network) logon from another
> internal host **in** `DeviceProcessEvents` correlated with `DeviceLogonEvents`,
> **distinguishable from normal by** the remote-origin network logon immediately
> preceding a `wmiprvse.exe`-parented `cmd.exe`/`powershell.exe`.

**Negative result looks like:** No `wmiprvse.exe` process spawned an interactive
shell within 5 minutes of an inbound network logon across the estate in the window.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all endpoints; prioritize servers and admin jump hosts.
- **Known-good baseline:** legitimate remote administration and monitoring tools
  use WMI. Baseline admin source hosts and service accounts.

## 4. Hunt Query

```kql
// WMI remote execution: wmiprvse.exe spawning a shell after a network logon.
let lookback = 7d;
let shells = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe"]);
let net_logons = materialize(
    DeviceLogonEvents
    | where Timestamp > ago(lookback)
    | where LogonType == "Network" and ActionType == "LogonSuccess"
    | project LogonTime = Timestamp, DeviceId, DeviceName, AccountName, RemoteIP
);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ (shells)
| join kind=inner net_logons on DeviceId
| where Timestamp between (LogonTime .. (LogonTime + 5m))
| project Timestamp, DeviceName, AccountName, RemoteIP,
          FileName, ProcessCommandLine, LogonTime
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Source-side: wmic /node used to launch remote process creation.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "/node:" and ProcessCommandLine has_any ("process","call","create")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** source host is a sanctioned admin/monitoring station;
  the account is an approved admin/service identity; activity falls in a known
  change window.
- **Suspicious indicators:** source is a workstation (not an admin host), the
  spawned shell runs encoded commands, or the target is a sensitive server the
  source account has no reason to administer.
- **Malicious confirmation:** the spawned command downloads/executes a payload,
  the chain continues to further hosts, or credentials were freshly stolen before
  the pivot.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1047` (`wmic /node: process call create`), or Impacket `wmiexec.py`
- **Expected hit:** `wmiprvse.exe` spawns a shell within 5m of a network logon; the wmiexec ADMIN$ redirect pattern is a fast-path tell.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** Impacket `wmiexec` characteristically spawns
`cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<ts> 2>&1` — the redirection to an
admin share is a high-confidence tell. Add that pattern as a fast-path filter.

---

## References

- https://attack.mitre.org/techniques/T1047/
