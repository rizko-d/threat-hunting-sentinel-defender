# Hunt Card — Service Stop & Recovery Tampering (Pre-Encryption)

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-IM-003 |
| **ATT&CK Technique** | T1489 / T1490 — Service Stop / Inhibit System Recovery |
| **Tactic** | Impact |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceProcessEvents`, `SecurityEvent` (7036/7040) |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High–Critical |

---

## 1. Trigger

Before encrypting, ransomware operators stop the services that would lock files or
block them — databases, mail servers, backup agents, and security tooling — to
maximize the number of files they can encrypt and to blind defenders. Scheduled
hunt; also triggered by any shadow-copy or mass-encryption lead.

## 2. Hypothesis

> **If** an adversary stops security/backup/database services **in order to**
> enable unobstructed encryption and evade defenses, **then** I would observe
> `net stop` / `sc stop` / `taskkill` / `Stop-Service` targeting a burst of
> security, backup, or database service names in a short window **in**
> `DeviceProcessEvents`, **distinguishable from normal by** the volume and *type*
> of services stopped together (security + backup + DB) from one host in minutes.

**Negative result looks like:** No host stopped a burst of security/backup/DB
services together outside an approved maintenance window in the scope.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all endpoints and servers; database/mail/file servers
  highest priority.
- **Known-good baseline:** patching and maintenance stop services in controlled
  windows. Baseline change-window timing and admin accounts.

## 4. Hunt Query

```kql
// Burst of security/backup/DB service stops — ransomware staging behavior.
let lookback = 7d;
let window = 10m;
let targets = dynamic([
    // security
    "sense","windefend","mssecsvc","sophos","cylance","carbonblack","crowdstrike",
    "mcafee","symantec","sentinelone","wdnissvc","securityhealthservice",
    // backup
    "veeam","backup","acronis","vss","volsnap","sql writer",
    // database / mail
    "mssql","sqlserver","mysql","postgres","oracle","msexchange","exchange"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| extend Cmd = tolower(ProcessCommandLine)
| where (FileName in~ ("net.exe","net1.exe","sc.exe") and Cmd has "stop")
    or (FileName =~ "taskkill.exe" and Cmd has "/f")
    or (FileName in~ ("powershell.exe","pwsh.exe") and Cmd has "stop-service")
| where Cmd has_any (targets)
| summarize
    StopCount = count(),
    ServiceSet = make_set(ProcessCommandLine, 40),
    Tools = make_set(FileName, 5),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, AccountName, bin(Timestamp, window)
| where StopCount >= 3            // multiple targeted stops in one window
| order by StopCount desc
```

**Pivots / follow-up queries:**

```kql
// Sentinel route: Service Control Manager stop events (System log).
Event
| where TimeGenerated > ago(7d)
| where Source == "Service Control Manager" and EventID in (7036, 7040)
| where RenderedDescription has_any ("stopped","disabled")
| where RenderedDescription has_any ("Defender","Veeam","Backup","SQL","Exchange","Sophos","CrowdStrike","Sense")
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```

## 5. Triage Guidance

- **Benign indicators:** a documented patch/maintenance window with a known admin
  cycling services; a single service restart for a legitimate config change.
- **Suspicious indicators:** security AND backup AND database services stopped
  together in minutes, `taskkill /f` against AV/EDR processes, activity outside
  any change window, stops immediately preceding file-write spikes.
- **Malicious confirmation:** correlates with shadow-copy deletion (TH-IM-001) or
  mass encryption (TH-IM-002); EDR tampering paired with the service stops.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1489` (`net stop`, `sc stop` against a lab DB/backup/AV service)
- **Expected hit:** 3+ targeted security/backup/DB service stops surface in one window (Defender), or SCM EID 7036/7040 (Sentinel).
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** The discriminator is *combination and velocity* — normal maintenance
touches one service class; ransomware staging hits security + backup + DB together
fast. This is the earliest of the three Impact hunts to fire, so it's the best
chance to isolate before encryption begins. Chain: TH-IM-003 (service stop) →
TH-IM-001 (shadow delete) → TH-IM-002 (encrypt).

---

## References

- https://attack.mitre.org/techniques/T1489/
- https://attack.mitre.org/techniques/T1490/
