# Hunt Card — Exfiltration Over C2 Channel

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-XF-001 |
| **ATT&CK Technique** | T1041 — Exfiltration Over C2 Channel |
| **Tactic** | Exfiltration |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceNetworkEvents`, `DeviceProcessEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High–Critical |

---

## 1. Trigger

Once an implant has C2, the cheapest exfil path is the channel it already owns —
staged data pushed back over the same beacon destination. Scheduled daily hunt;
also triggered whenever a beaconing hunt (TH-C2-001) flags a host↔destination
pair, or CTI reports a data-theft campaign.

## 2. Hypothesis

> **If** an adversary exfiltrates collected data over an established C2 channel
> **in order to** steal data without opening a new, noisier egress path, **then**
> I would observe a large volume of *sent* bytes from a host to the same external
> destination its beacon uses — a big upload skewed heavily outbound — **in**
> `DeviceNetworkEvents`, **distinguishable from normal by** the outbound byte
> volume and sent/received asymmetry to a rare destination owned by a non-browser
> process.

**Negative result looks like:** No host↔external-destination pair moved an
anomalous volume of sent bytes (heavily outbound-skewed) via a suspicious process
in the window, after excluding sanctioned upload/backup/SaaS endpoints.

## 3. Scope

- **Time window:** last 1–3 days (tight window keeps volume baselines meaningful)
- **Environment scope:** all endpoints with network telemetry; prioritize hosts
  already flagged for beaconing or with sensitive-data access.
- **Known-good baseline:** cloud backup, OS/telemetry uploads, source-control
  push, and SaaS sync move real outbound volume. Baseline and exclude those
  destinations/processes by domain and signer.

## 4. Hunt Query

```kql
// T1041: large outbound-skewed transfer to a rare external destination.
let lookback = 1d;
let min_sent_bytes = 10 * 1024 * 1024;   // 10 MB sent to one destination
let outbound_ratio = 5.0;                // sent >> received
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| where isnotempty(SentBytes) or isnotempty(ReceivedBytes)
| extend Sent = tolong(column_ifexists("SentBytes", long(null))),
         Recv = tolong(column_ifexists("ReceivedBytes", long(null)))
| where isnotempty(Sent)
| summarize
    TotalSent = sum(Sent),
    TotalRecv = sum(Recv),
    Conns = count(),
    Ports = make_set(RemotePort, 10),
    Procs = make_set(InitiatingProcessFileName, 10),
    SampleUrl = any(RemoteUrl),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, RemoteIP
| where TotalSent >= min_sent_bytes
    and TotalSent > (TotalRecv + 1) * outbound_ratio
| extend SentMB = round(TotalSent / 1024.0 / 1024.0, 2),
         OutRatio = round(todouble(TotalSent) / (TotalRecv + 1), 1)
| order by TotalSent desc
```

**Pivots / follow-up queries:**

```kql
// Correlate the exfil destination with a prior beacon: same RemoteIP, regular,
// low-volume connections BEFORE the big upload = C2 that then exfiltrated.
let suspect_ip = "<suspect_ip>";
DeviceNetworkEvents
| where Timestamp > ago(3d)
| where RemoteIP == suspect_ip and ActionType == "ConnectionSuccess"
| summarize Conns = count(),
            SentMB = round(sum(tolong(column_ifexists("SentBytes", long(0)))) / 1048576.0, 2),
            Procs = make_set(InitiatingProcessFileName, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, bin(Timestamp, 1h)
| order by Timestamp asc
```

```kql
// What process owns the exfil, and did it just touch sensitive files / archives?
let suspect_host = "<suspect_host>";
DeviceProcessEvents
| where Timestamp > ago(3d)
| where DeviceName =~ suspect_host
| where FileName in~ ("powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","curl.exe","certutil.exe")
    or ProcessCommandLine has_any ("Compress-Archive",".zip",".7z",".rar","Invoke-WebRequest","-OutFile","UploadFile")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** destination is a sanctioned backup/CDN/SaaS endpoint; the
  owning process is a signed backup/sync client with a documented upload purpose;
  outbound volume matches a known job window.
- **Suspicious indicators:** large sent-heavy transfer to a rare/young/raw-IP
  destination, owned by a non-browser process (`powershell`, `rundll32`,
  `regsvr32`, `curl`, `certutil`), especially to an IP that *also* showed regular
  low-volume beaconing beforehand.
- **Malicious confirmation:** the destination matches C2 IOCs, the process staged
  an archive of sensitive data immediately before the upload, or the same host
  shows correlated hands-on-keyboard collection activity.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1041` (exfiltrate a staged file over a lab C2), or a Sliver/Havoc beacon that uploads a multi-MB archive back to its own listener.
- **Expected hit:** the host↔listener pair surfaces with high `SentMB` and outbound `OutRatio`, and the beacon pivot shows regular low-volume connections preceding the spike.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (are SentBytes/ReceivedBytes populated in your telemetry?)
- [ ] Documented clear

**Notes:** `SentBytes`/`ReceivedBytes` are not always populated in
`DeviceNetworkEvents`; where they are sparse, pivot to `CommonSecurityLog` /
firewall flow logs for byte counts and keep this hunt as the process-attribution
layer. The strongest signal is the *correlation* — beacon regularity first, then a
volume spike to the same IP.

---

## References

- https://attack.mitre.org/techniques/T1041/