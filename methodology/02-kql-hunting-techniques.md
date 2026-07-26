# KQL Hunting Techniques

The KQL patterns I reach for in almost every hunt. These are hunting-oriented
(exploratory, wide-net, pivot-friendly) rather than detection-oriented (precise,
low-false-positive analytic rules). Same language, different mindset.

All examples run in both Sentinel (Log Analytics) and Defender XDR (Advanced
Hunting) unless noted. Swap table names for what you ingest.

---

## 1. Long-tail analysis (least frequency of occurrence)

The single most productive hunting technique. Adversary activity is *rare* by
definition. Stack a field and look at the bottom of the distribution.

```kql
// Rarest parent→child process relationships across the estate.
// Rare pairs are worth a look; common pairs are noise.
DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize Count = count(), Devices = dcount(DeviceId)
    by InitiatingProcessFileName, FileName
| order by Count asc
| take 100
```

The rare rows — `winword.exe → cmd.exe`, `sqlservr.exe → powershell.exe` — are
where you find the interesting behavior. (In an actual analytic rule I'd drop
the `take`; for hunting, capping the tail is fine.)

---

## 2. Stacking + rarity across a dimension

Find values seen on only one or two hosts — first-time-seen / low-prevalence
binaries, scheduled task names, service names, autorun entries.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName endswith ".exe"
| summarize DeviceCount = dcount(DeviceId), FirstSeen = min(Timestamp)
    by SHA256, FileName
| where DeviceCount <= 2                 // low prevalence
| where FirstSeen > ago(3d)              // recently appeared
| order by FirstSeen desc
```

Low prevalence + recently appeared = a strong hunting lead for planted tooling.

---

## 3. Time-series / beaconing (regular intervals)

C2 beacons check in on a near-constant cadence. Compute the interval between
successive connections and look for low jitter.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| project Timestamp, DeviceId, DeviceName, RemoteIP, InitiatingProcessFileName
| order by DeviceId, RemoteIP, Timestamp asc
| serialize
| extend PrevTime = prev(Timestamp),
         SameKey = (prev(strcat(DeviceId, RemoteIP)) == strcat(DeviceId, RemoteIP))
| extend IntervalSec = iff(SameKey, datetime_diff('second', Timestamp, PrevTime), long(null))
| where isnotempty(IntervalSec)
| summarize Conns = count(), MeanInt = avg(IntervalSec), Jitter = stdev(IntervalSec)
    by DeviceName, RemoteIP, InitiatingProcessFileName
| where Conns >= 12 and Jitter <= 30      // many check-ins, low jitter
| order by Jitter asc
```

Low `Jitter` relative to `MeanInt` = machine-like regularity = candidate beacon.

---

## 4. Joins — correlate across tables

The power move: correlate a process event with the logon that preceded it, or a
network connection with the process that made it.

```kql
// Remote logon (Type 3) immediately followed by process creation — lateral movement.
let logons =
    DeviceLogonEvents
    | where Timestamp > ago(1d)
    | where LogonType == "Network"
    | project LogonTime = Timestamp, DeviceId, AccountName, RemoteIP;
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "services.exe", "wsmprovhost.exe")
| join kind=inner logons on DeviceId
| where Timestamp between (LogonTime .. (LogonTime + 5m))
| project Timestamp, DeviceName, AccountName, RemoteIP,
          InitiatingProcessFileName, FileName, ProcessCommandLine
```

> Sentinel gotcha: when a tabular `let` is joined, wrap it in `materialize()`
> for performance and to avoid `'join' operator: Failed to resolve` errors on
> larger sets.

---

## 5. mv-expand — unpack arrays and dynamic fields

Many XDR fields are dynamic (JSON). `mv-expand` and dot-notation crack them open.

```kql
DeviceEvents
| where ActionType == "AntivirusDetection"
| extend Threat = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ThreatName = Threat.ThreatName, FileName
```

---

## 6. Rare-value hunting with `make_set` / `dcount`

Fan-out detection: one account touching an abnormal number of distinct hosts
(discovery, spraying, or lateral movement).

```kql
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == "Network" and ActionType == "LogonSuccess"
| summarize Hosts = dcount(DeviceId), HostSet = make_set(DeviceName, 50)
    by AccountName
| where Hosts > 30                        // one identity, many machines
| order by Hosts desc
```

---

## 7. String / entropy hunting for obfuscation

Encoded PowerShell, long base64 blobs, high-entropy command lines.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String", "-w hidden", "IEX", "Invoke-Expression")
| extend CmdLen = strlen(ProcessCommandLine)
| where CmdLen > 300                       // long, obfuscated invocations
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, CmdLen
| order by CmdLen desc
```

---

## Hunting-mode vs detection-mode KQL

| | Hunting query | Detection (analytic) rule |
|---|---|---|
| Goal | Explore, find leads | Fire precisely, low FP |
| Breadth | Wide net, tolerate noise | Tight, tuned |
| `take` / limits | Fine while exploring | Never — Sentinel caps results |
| Output | Rows for a human to pivot on | Structured alert entities |
| Lifecycle | Throwaway / iterative | Version-controlled, tested |

When a hunting query proves reliably precise, I graduate it into an analytic
rule (a detection). Until then it lives here as a hunt.

---

## Performance notes

- Filter on `Timestamp`/`TimeGenerated` **first** — it's the partition key.
- Project only the columns you need before a `join` or `summarize`.
- `has` / `has_any` are faster than `contains` (term-indexed).
- `materialize()` any `let` reused in multiple joins.
- Prefer `dcount()` (approximate, fast) over `count(distinct)` at scale.
