# Hunt Card — Mass File Modification / Ransomware Encryption

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-IM-002 |
| **ATT&CK Technique** | T1486 — Data Encrypted for Impact |
| **Tactic** | Impact |
| **Platform(s)** | Defender XDR |
| **Data Source(s)** | `DeviceFileEvents`, `DeviceProcessEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | Critical |

---

## 1. Trigger

The encryption event itself — the moment of impact. Detecting the *behavioral
shape* of mass encryption (one process rewriting thousands of files at high
velocity, appending a new extension, dropping ransom notes) catches novel
ransomware families that signatures miss. Scheduled daily; also triggered by any
shadow-copy-deletion hit (TH-IM-001).

## 2. Hypothesis

> **If** ransomware encrypts files for impact, **then** I would observe a single
> process modifying/creating an abnormally large number of files across many
> directories in a short window, often appending a uniform new extension and
> writing ransom-note files **in** `DeviceFileEvents`, **distinguishable from
> normal by** the velocity and breadth of file modifications from one process far
> above any legitimate application baseline.

**Negative result looks like:** No single non-allowlisted process modified more
than N files across M directories within a short window, and no ransom-note
filename pattern appeared, across the estate in the window.

## 3. Scope

- **Time window:** last 3 days (fast, high-severity)
- **Environment scope:** all endpoints; file servers highest priority (blast
  radius).
- **Known-good baseline:** backup, indexing (Search), sync clients (OneDrive),
  and compilers touch many files. Baseline and allowlist by initiating process.

## 4. Hunt Query

```kql
// Mass file modification by a single process — ransomware encryption shape.
let lookback = 3d;
let file_threshold = 200;         // files touched by one process in the window
let dir_threshold = 20;           // spread across many directories
let window = 10m;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileModified", "FileCreated", "FileRenamed")
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe","OneDrive.exe","SearchIndexer.exe","backup.exe","Dropbox.exe",
    "googledrivesync.exe","msedge.exe","chrome.exe","explorer.exe"
  )
| summarize
    FilesTouched = dcount(FolderPath),
    Dirs = dcount(tostring(parse_path(FolderPath).DirectoryPath)),
    ExtSet = make_set(tostring(parse_path(FolderPath).Extension), 25),
    Sample = make_set(FolderPath, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(Timestamp, window)
| where FilesTouched >= file_threshold and Dirs >= dir_threshold
| extend DistinctExtensions = array_length(ExtSet)
| order by FilesTouched desc
```

**Pivots / follow-up queries:**

```kql
// Ransom-note drop: same suspicious filenames appearing across many folders.
DeviceFileEvents
| where Timestamp > ago(3d)
| where ActionType in ("FileCreated","FileModified")
| where FileName matches regex @"(?i)(readme|recover|restore|decrypt|how[_ -]?to|ransom).*\.(txt|html|hta)$"
    or FileName matches regex @"(?i)^!+.*\.(txt|html)$"
| summarize Folders = dcount(FolderPath), Devices = dcount(DeviceName),
            Sample = make_set(FolderPath, 15) by FileName, InitiatingProcessFileName
| where Folders >= 5
| order by Folders desc
```

## 5. Triage Guidance

- **Benign indicators:** the process is a known backup/sync/indexing agent; a
  developer build touching many files in a project tree; a bulk media transcode.
- **Suspicious indicators:** a single uniform new extension appended across many
  file types, spread across user-document and share directories, an unsigned or
  newly-seen initiating binary, high files-per-second rate.
- **Malicious confirmation:** ransom notes present, shadow copies just deleted
  (correlate TH-IM-001), original extensions replaced en masse, security tooling
  killed just prior.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** Behavioral, not signature-based — this catches families with no known
hash. The strongest correlation is the trio: shadow-copy delete (TH-IM-001) →
mass modify (this) → ransom-note drop (pivot query). Seeing two of the three is an
active-incident call. Tune thresholds to your file-server baselines.

---

## References

- https://attack.mitre.org/techniques/T1486/
