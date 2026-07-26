# Hunt Card — LSASS Credential Dumping

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-CA-002 |
| **ATT&CK Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access |
| **Platform(s)** | Defender XDR |
| **Data Source(s)** | `DeviceProcessEvents`, `DeviceEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | Critical |

---

## 1. Trigger

LSASS dumping is the canonical post-exploitation credential grab (Mimikatz,
procdump, comsvcs.dll, direct handle access). Scheduled hunt; also triggered by
any endpoint alert mentioning `lsass`.

## 2. Hypothesis

> **If** an adversary dumps LSASS **in order to** harvest credentials from memory,
> **then** I would observe a non-system process opening a handle to, or reading
> the memory of, `lsass.exe` — or a known dumping utility/command pattern
> targeting it — **in** `DeviceProcessEvents`/`DeviceEvents`, **distinguishable
> from normal by** the initiating process not being a legitimate AV/EDR/OS
> component.

**Negative result looks like:** No non-allowlisted process accessed LSASS memory
or invoked a known LSASS-dump command pattern across the endpoint estate in the
7-day window.

## 3. Scope

- **Time window:** last 7 days (near-real-time class threat)
- **Environment scope:** all Defender for Endpoint onboarded devices
- **Known-good baseline:** AV/EDR agents, `MsMpEng.exe`, `taskmgr.exe` (user-driven
  dumps), backup/DLP agents legitimately touch LSASS. Allowlist by signer.

## 4. Hunt Query

```kql
// LSASS dump via known command-line patterns and tooling.
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where
    // comsvcs.dll MiniDump
    (ProcessCommandLine has "comsvcs" and ProcessCommandLine has "MiniDump")
    // procdump against lsass
    or (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
    // rundll32 minidump
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has_all ("comsvcs.dll", "#24"))
    // direct references to lsass in a dump context
    or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("dump", "-ma", "MiniDump", "sekurlsa"))
    // task manager / other creating an lsass dmp file
    or ProcessCommandLine has_any ("lsass.dmp", "lsass.DMP")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Handle-access route: sensitive process access to lsass captured in DeviceEvents.
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("OpenProcessApiCall", "ReadProcessMemoryApiCall")
| where FileName =~ "lsass.exe" or AdditionalFields has "lsass"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "MsSense.exe", "csrss.exe", "wininit.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName, AdditionalFields
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** initiating process is a signed AV/EDR/backup/DLP agent;
  a user manually created a dump via Task Manager for troubleshooting (rare,
  should be justified).
- **Suspicious indicators:** `rundll32 comsvcs.dll #24`, `procdump` against
  lsass, any `sekurlsa` reference, an unsigned or newly-seen binary opening LSASS.
- **Malicious confirmation:** the resulting dump file is exfiltrated, or the host
  shows follow-on lateral movement using freshly harvested credentials.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1003.001` (comsvcs MiniDump `#24`, procdump `-ma lsass`, Mimikatz `sekurlsa`)
- **Expected hit:** the primary query fires on the `comsvcs`/`procdump`/`sekurlsa` command-line, or the `DeviceEvents` pivot on OpenProcess to lsass.exe.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** Defender has built-in ASR rules ("Block credential stealing from
LSASS") — a hunt hit where ASR did *not* block is itself a finding (rule in audit
mode, or an evasion). Cross-check with `AlertInfo`.

---

## References

- https://attack.mitre.org/techniques/T1003/001/
- LOLBAS: comsvcs.dll MiniDump technique
