# Hunt Card — Exfiltration to Cloud Storage

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-XF-002 |
| **ATT&CK Technique** | T1567.002 — Exfiltration to Cloud Storage |
| **Tactic** | Exfiltration |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DeviceNetworkEvents`, `DeviceProcessEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

Public file-sharing services (MEGA, Dropbox, Google Drive, anonfiles, raw S3
buckets) are attacker-friendly exfil sinks — they blend into normal web traffic.
The tell is *who* is talking to them: a non-browser or unusual process. Scheduled
daily hunt; also triggered by DLP alerts or `rclone`/`megatools` detections.

## 2. Hypothesis

> **If** an adversary uploads collected data to a public cloud-storage service
> **in order to** exfiltrate over trusted, TLS-wrapped web infrastructure, **then**
> I would observe connections to known file-sharing domains initiated by a
> **non-browser** or unusual process (`rclone`, `curl`, `powershell`, `megatools`)
> **in** `DeviceNetworkEvents`, **distinguishable from normal by** the initiating
> process — legitimate cloud-storage use rides browsers or vendor sync clients,
> not scripting/transfer tooling.

**Negative result looks like:** No connections to file-sharing services from
non-browser/non-sanctioned-sync processes in the window, after excluding approved
backup and vendor sync clients.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all endpoints with network telemetry; prioritize hosts
  with access to sensitive data stores.
- **Known-good baseline:** the org may sanction OneDrive/Dropbox/Google Drive via
  official sync clients and browsers. Baseline those process↔service pairs and
  exclude them; everything else to these domains is in scope.

## 4. Hunt Query

```kql
// T1567.002: uploads to public file-sharing services by non-browser processes.
let lookback = 7d;
let sharing_domains = dynamic([
    "mega.nz","mega.co.nz","userstorage.mega.co.nz",
    "dropbox.com","dropboxusercontent.com",
    "drive.google.com","googleapis.com","storage.googleapis.com",
    "anonfiles.com","bayfiles.com","gofile.io","file.io","transfer.sh",
    "wetransfer.com","pcloud.com","mediafire.com","sendspace.com",
    "s3.amazonaws.com","amazonaws.com","backblazeb2.com","b2-api.com"]);
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe",
    "opera.exe","iexplore.exe","safari.exe"]);
let sanctioned_sync = dynamic(["onedrive.exe","dropbox.exe","googledrivefs.exe",
    "googledrivesync.exe","filecoauth.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteUrl)
| extend Host = tolower(tostring(parse_url(RemoteUrl).Host))
| where Host has_any (sharing_domains)
| extend Proc = tolower(InitiatingProcessFileName)
| where Proc !in (browsers) and Proc !in (sanctioned_sync)
| summarize
    Conns = count(),
    SentMB = round(sum(tolong(column_ifexists("SentBytes", long(0)))) / 1048576.0, 2),
    Hosts = make_set(Host, 15),
    Urls = make_set(RemoteUrl, 15),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by SentMB desc, Conns desc
```

**Pivots / follow-up queries:**

```kql
// Confirm the tooling: rclone/megatools/curl/powershell launching an upload.
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("rclone.exe","megatools.exe","megacmd.exe","curl.exe",
        "powershell.exe","pwsh.exe","aws.exe","gsutil.cmd","gdrive.exe")
    or ProcessCommandLine has_any ("rclone","mega.nz","transfer.sh","gofile",
        "anonfiles","aws s3 cp","aws s3 sync","Invoke-RestMethod","UploadFile",
        "PutObject")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Did an archive get built right before the upload? (staging → exfil chain)
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any ("Compress-Archive","-r ",".7z ","rar a",
        ".zip","tar -c")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** the process is an approved sync client or browser; the
  destination is a sanctioned corporate tenant; the user routinely uses that
  service for legitimate work.
- **Suspicious indicators:** `rclone`/`megatools`/`curl`/`powershell` talking to
  MEGA/anonfiles/gofile/transfer.sh; large `SentMB` to a personal/anonymous
  service; upload immediately preceded by an archive-creation command.
- **Malicious confirmation:** the destination account is attacker-controlled, the
  uploaded archive contained sensitive/staged data, or the transfer tooling was
  dropped by a prior intrusion stage.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** an authorized `rclone copy ./lab-data remote:` to a lab cloud bucket, or `Invoke-AtomicTest T1567.002` (upload a benign file to a file-sharing service).
- **Expected hit:** the primary query surfaces the host with a non-browser process (`rclone.exe`/`curl.exe`) connecting to the sharing domain, and the process pivot shows the upload command line.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is RemoteUrl populated? are sanctioned syncs baselined?)
- [ ] Documented clear

**Notes:** The `sharing_domains` and `sanctioned_sync` lists are the tuning
surface — promote them to a watchlist / external data so SOC can maintain them.
Raw S3/GCS entries are noisy in cloud-native shops; if so, gate them behind a
`SentMB` threshold rather than dropping them, so bulk PutObject exfil still surfaces.

---

## References

- https://attack.mitre.org/techniques/T1567/002/