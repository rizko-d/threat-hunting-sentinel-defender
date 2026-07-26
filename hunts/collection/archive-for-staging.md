# Hunt Card — Archive Collected Data for Staging (Archive via Utility)

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-CO-002 |
| **ATT&CK Technique** | T1560.001 Archive Collected Data: Archive via Utility |
| **Tactic** | Collection |
| **Platform(s)** | Windows (Defender XDR / Microsoft Sentinel) |
| **Data Source(s)** | DeviceProcessEvents, DeviceFileEvents, SecurityEvent |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

## 1. Trigger

Before exfiltration, adversaries stage collected data by compressing sensitive directories with command-line archivers (`rar.exe`, `7z.exe`, `tar.exe`, WinZip, or PowerShell `Compress-Archive`), often with password protection and split volumes to evade DLP and reduce transfer footprint. A single large archive dropped into a temp/staging path — sourced from user profile, document shares, or database/backup dirs — is a strong pre-exfil indicator. Hunt this now whenever collection-tactic activity, credential access, or lateral movement has been observed on a host.

## 2. Hypothesis

> **If** an adversary performs archiving of sensitive directories with a command-line utility **in order to** stage collected data for exfiltration, **then** I would observe archiver process command lines referencing sensitive source paths and a large output archive **in** DeviceProcessEvents / DeviceFileEvents, **distinguishable from normal by** password/split-volume flags, unusual staging output folders (Temp/ProgramData/Public), and archives whose size and source paths do not match sanctioned backup/IT jobs.

**Negative result looks like:** All archiving is performed by sanctioned backup/deployment software under service accounts writing to designated backup targets; no interactive user or script host compresses profile/share/database directories into temp with password or split flags.

## 3. Scope

- **Time window:** Last 14 days (adjust `lookback`).
- **Environment scope:** All managed Windows endpoints and file/DB servers; prioritize hosts holding sensitive data.
- **Known-good baseline:** Sanctioned backup agents (Veeam, Commvault, Windows Server Backup), software packaging jobs, and IT-approved 7-Zip usage. Baseline their service accounts, source paths, and output targets. Set `minArchiveBytes` to your environment's meaningful-size floor.

## 4. Hunt Query

```kql
// TH-CO-002 — Archive collected data for staging (T1560.001)
let lookback = 14d;
let archivers = dynamic(["rar.exe","winrar.exe","7z.exe","7za.exe","7zr.exe",
    "tar.exe","zip.exe","winzip.exe","wzzip.exe","pkzip.exe","peazip.exe"]);
let sensitivePaths = dynamic(["\\Users\\","\\Documents\\","\\Desktop\\",
    "\\Downloads\\","\\AppData\\Roaming\\","\\ProgramData\\",
    "\\Finance","\\HR","\\Backup","\\Database","\\SQL","\\Shares\\",
    "\\Confidential","\\.ssh","\\.aws"]);
let stagingPaths = dynamic(["\\Temp\\","\\Windows\\Temp\\","\\ProgramData\\",
    "\\Users\\Public\\","\\AppData\\Local\\Temp\\","\\PerfLogs\\","\\$Recycle"]);
let suspiciousFlags = dynamic([" -p", " -hp", " -v", "-r ", " -m5", " a ",
    "-ppassword", "Compress-Archive"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (archivers)
    or (FileName in~ ("powershell.exe","pwsh.exe")
        and ProcessCommandLine has "Compress-Archive")
| where ProcessCommandLine has_any (sensitivePaths)
    or ProcessCommandLine has_any (stagingPaths)
| extend HasSuspiciousFlag = ProcessCommandLine has_any (suspiciousFlags)
| extend TouchesSensitive  = ProcessCommandLine has_any (sensitivePaths)
| extend WritesToStaging   = ProcessCommandLine has_any (stagingPaths)
| where TouchesSensitive or (WritesToStaging and HasSuspiciousFlag)
| project Timestamp, DeviceName, AccountName, FileName,
    InitiatingProcessFileName, ProcessCommandLine, FolderPath,
    HasSuspiciousFlag, TouchesSensitive, WritesToStaging, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Pivot A — large archive files written to staging paths (T1560.001 output)
let lookback = 14d;
let minArchiveBytes = 20000000; // ~20 MB floor; tune to environment
let archiveExt = dynamic([".rar",".7z",".zip",".tar",".gz",".tgz",
    ".cab",".arj",".ace",".001"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated","FileModified")
| where FileName has_any (archiveExt)
| where FolderPath has_any ("\\Temp\\","\\ProgramData\\","\\Users\\Public\\",
    "\\Windows\\Temp\\","\\AppData\\Local\\Temp\\","\\PerfLogs\\","\\$Recycle")
| where isnotempty(FileSize) and FileSize >= minArchiveBytes
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
    FileSizeMB = round(FileSize / 1048576.0, 1),
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by FileSizeMB desc
```

```kql
// Pivot B — Sentinel: archiver command lines via process-creation (EventID 4688)
let lookback = 14d;
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4688
| where NewProcessName has_any ("rar.exe","7z.exe","7za.exe","tar.exe",
    "winrar.exe","winzip.exe")
    or CommandLine has "Compress-Archive"
| where CommandLine has_any (" -hp"," -p"," -v","\\Users\\","\\Backup",
    "\\Finance","\\HR","\\.ssh","\\.aws")
| project TimeGenerated, Computer, Account, NewProcessName,
    ParentProcessName, CommandLine
| sort by TimeGenerated desc
```

## 5. Triage Guidance

- **Benign indicators:** Sanctioned backup/packaging software under a known service account, writing to designated backup targets on schedule; developer packaging build artifacts in a project folder; no password/split flags on unexpected sources.
- **Suspicious indicators:** Interactive user or script host archiving profile/share/database dirs into `\Temp\`/`Public`/`ProgramData`; use of `-hp`/`-p` (password) and `-v` (split volume) flags; archiver launched by an unusual parent (winword, outlook, rundll32, mshta); large single archive assembled quickly.
- **Malicious confirmation:** Archive-to-staging immediately followed by outbound transfer (DeviceNetworkEvents to rare destination / cloud storage), or the archive deleted after transfer; source paths spanning multiple users/shares; renamed archiver binary or unsigned utility; correlation with prior collection (screenshot/clipboard) or credential access.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1560.001` — or manually run `7z.exe a -phunt123 C:\Windows\Temp\loot.7z C:\Users\%USERNAME%\Documents\` and `Compress-Archive -Path $env:USERPROFILE\Documents\* -DestinationPath C:\ProgramData\loot.zip` in the lab, producing an archive above `minArchiveBytes`.
- **Expected hit:** Primary query returns the archiver process with the sensitive source path and password flag; Pivot A returns the resulting archive in the staging folder above the size floor.
- **If it does NOT fire:** check data-source ingestion, the time window, and any baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** Capture the archiver command line, source paths, output archive path/size, process lineage, and any subsequent network transfer. Confirm whether the archive was password-protected or split. Tune `minArchiveBytes`, `sensitivePaths`, and the sanctioned-backup baseline before promoting to an analytic rule. If `FileSize` is not populated in DeviceFileEvents for your tenant, rely on the process-command-line detection (primary + Pivot B) and file a visibility gap.

## References

- https://attack.mitre.org/techniques/T1560/001/
- https://attack.mitre.org/techniques/T1560/