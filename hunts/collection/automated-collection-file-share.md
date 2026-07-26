# Hunt Card — Automated Collection from Network Shared Drives

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-CO-003 |
| **ATT&CK Technique** | T1119 Automated Collection, T1039 Data from Network Shared Drive |
| **Tactic** | Collection |
| **Platform(s)** | Windows (Defender XDR / Microsoft Sentinel) |
| **Data Source(s)** | DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

## 1. Trigger

Adversaries automate the harvesting of documents from local disks and mapped/UNC network shares using scripted loops (`Get-ChildItem`/`robocopy`/`xcopy`/`findstr`) that recurse and filter by extension (docx, xlsx, pdf, pst, kdbx, config, keys). Automated collection produces a burst of reads/copies across many files and often reaches out to `\\server\share` paths or SMB (TCP 445) hosts the endpoint does not normally touch. Hunt this now after initial access, credential access, or when a host suddenly enumerates unfamiliar shares.

## 2. Hypothesis

> **If** an adversary performs automated, scripted collection across local and network shared drives **in order to** bulk-harvest sensitive documents for exfiltration, **then** I would observe recursive file-search/copy command lines and a burst of file reads from UNC/mapped paths **in** DeviceProcessEvents / DeviceFileEvents / DeviceNetworkEvents, **distinguishable from normal by** script-host-driven recursion with extension filters, access to shares outside the user's normal set, and abnormally high file-touch volume in a short window.

**Negative result looks like:** File-share access matches each user's normal set of departmental shares, driven by interactive Office/Explorer usage; no script host recursively copies or greps documents by extension, and no host shows an anomalous burst of SMB reads from unfamiliar servers.

## 3. Scope

- **Time window:** Last 14 days (adjust `lookback`).
- **Environment scope:** All managed Windows endpoints with share access; prioritize hosts of users with broad share permissions and file/DB servers.
- **Known-good baseline:** Per-user/department normal share set, backup/sync agents (OneDrive, backup jobs), and search-indexing services. Baseline typical file-touch volume per host per hour; set `burstThreshold` accordingly.

## 4. Hunt Query

```kql
// TH-CO-003 — Automated collection from local & network shares (T1119 / T1039)
let lookback = 14d;
let collectors = dynamic(["robocopy.exe","xcopy.exe","copy.exe","esentutl.exe",
    "findstr.exe","find.exe","forfiles.exe","tar.exe"]);
let scriptHosts = dynamic(["powershell.exe","pwsh.exe","cmd.exe",
    "wscript.exe","cscript.exe"]);
let recursionTokens = dynamic(["-Recurse","/S ","/E ","Get-ChildItem",
    "gci ","dir /s","/mir","robocopy"]);
let targetExt = dynamic([".docx",".xlsx",".pptx",".pdf",".pst",".ost",
    ".kdbx",".config",".key",".pem",".rdp",".txt",".csv"]);
let uncTokens = dynamic(["\\\\","net use ","New-PSDrive","-Path \\\\"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (collectors) or FileName in~ (scriptHosts)
| where ProcessCommandLine has_any (recursionTokens)
| extend FiltersByExt = ProcessCommandLine has_any (targetExt)
| extend TouchesShare  = ProcessCommandLine has_any (uncTokens)
| where FiltersByExt or TouchesShare
| project Timestamp, DeviceName, AccountName, FileName,
    InitiatingProcessFileName, ProcessCommandLine, FolderPath,
    FiltersByExt, TouchesShare, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Pivot A — burst of file reads/copies from UNC/network share paths (T1039)
let lookback = 14d;
let burstThreshold = 100; // files touched per host/user/hour; tune to baseline
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath startswith "\\\\"          // UNC network share path
    or FolderPath matches regex @"^[D-Z]:\\"  // mapped network drive letters
| summarize FileCount = count(),
    DistinctFolders = dcount(FolderPath),
    SampleFiles = make_set(FileName, 15),
    Initiators = make_set(InitiatingProcessFileName, 10)
    by DeviceName, AccountName, bin(Timestamp, 1h)
| where FileCount >= burstThreshold
| order by FileCount desc
```

```kql
// Pivot B — endpoints reaching new SMB (445) hosts they don't normally use
let lookback = 14d;
let baselineWindow = 30d;
let baseline = DeviceNetworkEvents
    | where Timestamp between (ago(baselineWindow) .. ago(lookback))
    | where RemotePort == 445
    | distinct DeviceName, RemoteIP;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemotePort == 445 and ActionType == "ConnectionSuccess"
| join kind=leftanti baseline on DeviceName, RemoteIP
| summarize Connections = count(),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
    Initiators = make_set(InitiatingProcessFileName, 10)
    by DeviceName, AccountName = InitiatingProcessAccountName, RemoteIP
| order by Connections desc
```

## 5. Triage Guidance

- **Benign indicators:** Backup/sync agents (OneDrive, Veeam) or indexing services performing broad reads under known service accounts; a user opening files interactively via Office/Explorer within their normal share set; robocopy run by IT to a sanctioned target.
- **Suspicious indicators:** Script host recursing with extension filters (`Get-ChildItem -Recurse -Include *.docx,*.kdbx`); `robocopy /mir`/`xcopy /s` against `\\server\share`; a host suddenly touching >`burstThreshold` files/hour from UNC paths; connections to SMB hosts never seen in baseline.
- **Malicious confirmation:** Automated collection followed by archiving (see TH-CO-002) and outbound transfer; harvesting across multiple shares/users outside the account's role; `net use`/`New-PSDrive` to attacker-mapped shares; collector binary renamed or launched by an unusual parent; correlation with prior credential access.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1119` and `Invoke-AtomicTest T1039` — or manually run `Get-ChildItem -Path \\lab-fileserver\share -Recurse -Include *.docx,*.xlsx,*.pdf | Copy-Item -Destination C:\Windows\Temp\loot` and `robocopy \\lab-fileserver\share C:\Windows\Temp\loot *.docx /S` from a lab host.
- **Expected hit:** Primary query returns the script-host/robocopy process with recursion + extension/UNC tokens; Pivot A returns the file-read burst from the UNC path; Pivot B surfaces the new SMB host if it was outside baseline.
- **If it does NOT fire:** check data-source ingestion, the time window, and any baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** Record the collector command line, target shares/extensions, file-touch volume, involved shares/servers, and any subsequent archiving or exfil. Confirm whether the accessed shares fall within the account's role. Tune `burstThreshold` to per-host baseline and refine the per-user normal share set before promoting to an analytic rule. If `InitiatingProcessAccountName` is sparse in DeviceNetworkEvents, pivot on DeviceName and correlate to the DeviceProcessEvents hit.

## References

- https://attack.mitre.org/techniques/T1119/
- https://attack.mitre.org/techniques/T1039/