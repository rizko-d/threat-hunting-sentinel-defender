# Hunt Card — C2 Beaconing by Interval Regularity

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-C2-001 |
| **ATT&CK Technique** | T1071.001 — Application Layer Protocol: Web Protocols |
| **Tactic** | Command and Control |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceNetworkEvents`, `CommonSecurityLog` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

Every implant with a C2 channel beacons. Scheduled daily hunt; also triggered
whenever a new C2 framework or malleable profile is reported in CTI.

## 2. Hypothesis

> **If** an implant beacons to C2 **in order to** receive tasking, **then** I would
> observe repeated outbound connections from one host to one external destination
> at a near-constant interval with low jitter **in** `DeviceNetworkEvents`,
> **distinguishable from normal by** the regularity of the inter-connection
> interval (low standard deviation) over many connections.

**Negative result looks like:** No host↔external-destination pair showed ≥12
connections with interval standard deviation ≤30s and a non-trivial mean interval
in the window (after excluding known telemetry/update endpoints).

## 3. Scope

- **Time window:** last 1–3 days (tight window sharpens interval math)
- **Environment scope:** all endpoints with network telemetry
- **Known-good baseline:** software update, telemetry, OCSP/CRL, time sync, SaaS
  keep-alives all poll regularly. Exclude known-good destinations by domain/IP.

## 4. Hunt Query

```kql
// C2 beaconing: regular interval, low jitter, to external destinations.
let lookback = 1d;
let min_connections = 12;
let max_jitter_sec = 30;
let min_mean_interval_sec = 30;      // ignore very chatty sub-30s app traffic
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| project Timestamp, DeviceId, DeviceName, RemoteIP,
          RemoteUrl = column_ifexists("RemoteUrl",""), InitiatingProcessFileName
| order by DeviceId, RemoteIP, Timestamp asc
| serialize
| extend SameKey = (prev(strcat(DeviceId, RemoteIP)) == strcat(DeviceId, RemoteIP)),
         PrevTime = prev(Timestamp)
| extend IntervalSec = iff(SameKey, datetime_diff('second', Timestamp, PrevTime), long(null))
| where isnotempty(IntervalSec)
| summarize
    Conns = count(),
    MeanInterval = avg(IntervalSec),
    Jitter = stdev(IntervalSec),
    Processes = make_set(InitiatingProcessFileName, 10),
    SampleUrl = any(RemoteUrl)
    by DeviceName, RemoteIP
| where Conns >= min_connections
    and MeanInterval >= min_mean_interval_sec
    and Jitter <= max_jitter_sec
| extend RegularityScore = round(1.0 - (Jitter / (MeanInterval + 1)), 3)
| order by RegularityScore desc
```

**Pivots / follow-up queries:**

```kql
// Pivot: reputation + what process owns the beacon on the flagged host.
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where DeviceName =~ "<suspect_host>" and RemoteIP == "<suspect_ip>"
| summarize Conns=count(), Ports=make_set(RemotePort,10), Procs=make_set(InitiatingProcessFileName,10),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
| extend DurationHours = datetime_diff('hour', LastSeen, FirstSeen)
```

## 5. Triage Guidance

- **Benign indicators:** destination is a known update/telemetry/CDN endpoint;
  the owning process is a signed OS/vendor component with a documented polling
  cadence.
- **Suspicious indicators:** destination is a young/rare/uncategorized domain or
  raw IP, the owning process is unusual (or `rundll32`/`regsvr32`), consistent
  small payloads, activity spans off-hours.
- **Malicious confirmation:** destination matches C2 IOCs, TLS cert is
  self-signed/default-profile, or the host shows correlated hands-on-keyboard
  activity.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** a lab C2 (Sliver/Havoc/Cobalt Strike) beacon at a fixed sleep interval, or `Invoke-AtomicTest T1071.001`
- **Expected hit:** the host<->destination pair surfaces with `RegularityScore` high (low jitter over >=12 connections).
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** Sophisticated beacons add jitter. Loosen `max_jitter_sec` and hunt on
the *ratio* `RegularityScore` rather than absolute stdev to catch jittered
profiles — trade precision for recall depending on the threat.

---

## References

- https://attack.mitre.org/techniques/T1071/001/
