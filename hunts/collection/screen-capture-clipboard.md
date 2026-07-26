# Hunt Card — Screen Capture & Clipboard Data Theft

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-CO-001 |
| **ATT&CK Technique** | T1113 Screen Capture, T1115 Clipboard Data |
| **Tactic** | Collection |
| **Platform(s)** | Windows (Defender XDR / Microsoft Sentinel) |
| **Data Source(s)** | DeviceProcessEvents, DeviceFileEvents, DeviceEvents |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | Medium |

## 1. Trigger

Post-compromise operators frequently grab screenshots and scrape the clipboard to harvest credentials, MFA codes, and sensitive on-screen data that never touches disk elsewhere. Commodity RATs and living-off-the-land scripts routinely call PowerShell's `System.Windows.Forms` / `System.Drawing` screen-grab APIs or `Get-Clipboard`, and utilities like `nircmd`, `screenshot.exe`, or `boxcutter` produce image files in temp/staging paths. Hunt this now when there is elevated interactive activity on high-value hosts or a fresh foothold on an endpoint.

## 2. Hypothesis

> **If** an adversary performs screen capture and clipboard scraping **in order to** harvest on-screen secrets and credentials, **then** I would observe screenshot-related API/tool invocation and image files written to temp/staging paths, plus clipboard-read command lines **in** DeviceProcessEvents / DeviceFileEvents / DeviceEvents, **distinguishable from normal by** non-interactive parent processes (script hosts, rundll32, non-standard binaries) writing images into hidden/temp directories rather than user-initiated snipping in normal user paths.

**Negative result looks like:** No script host or unusual binary reads the clipboard or captures the screen; the only screenshot activity comes from legitimate signed tools (SnippingTool, ScreenClippingHost, Teams/Zoom) writing to expected user picture folders.

## 3. Scope

- **Time window:** Last 14 days (adjust `lookback` let-statement).
- **Environment scope:** All managed Windows endpoints; prioritize workstations of privileged users, jump hosts, and VDI.
- **Known-good baseline:** SnippingTool.exe, ScreenClippingHost.exe, ScreenSketch, Teams/Zoom/Slack capture, Greenshot/ShareX (if sanctioned), and OS accessibility tooling. Baseline the normal picture/screenshot output folders for your environment.

## 4. Hunt Query

```kql
// TH-CO-001 — Screen Capture & Clipboard Data theft (T1113 / T1115)
let lookback = 14d;
let clipCmdline = dynamic(["Get-Clipboard", "System.Windows.Forms.Clipboard",
    "Clipboard]::GetText", "Clipboard]::GetImage", "powershell -c $clip",
    "System.Windows.Clipboard"]);
let capCmdline = dynamic(["CopyFromScreen", "System.Drawing.Bitmap",
    "Graphics]::FromImage", "nircmd*savescreenshot", "boxcutter", "screenshot"]);
let benignImgTools = dynamic(["snippingtool.exe","screenclippinghost.exe",
    "screensketch.exe","greenshot.exe","sharex.exe","teams.exe","ms-teams.exe",
    "zoom.exe","slack.exe","chrome.exe","msedge.exe"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any (clipCmdline)
    or ProcessCommandLine has_any (capCmdline)
| where not(InitiatingProcessFileName in~ (benignImgTools))
| where FileName !in~ (benignImgTools)
| extend Behavior = case(
    ProcessCommandLine has_any (clipCmdline), "ClipboardRead(T1115)",
    ProcessCommandLine has_any (capCmdline),  "ScreenCapture(T1113)",
    "Unknown")
| project Timestamp, DeviceName, AccountName, Behavior, FileName,
    InitiatingProcessFileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Pivot A — image files written to temp/staging by script hosts (T1113 output)
let lookback = 14d;
let scriptHosts = dynamic(["powershell.exe","pwsh.exe","cmd.exe","wscript.exe",
    "cscript.exe","rundll32.exe","mshta.exe","regsvr32.exe"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated","FileModified")
| where FileName endswith ".png" or FileName endswith ".jpg"
    or FileName endswith ".jpeg" or FileName endswith ".bmp"
| where InitiatingProcessFileName in~ (scriptHosts)
| where FolderPath has_any ("\\Temp\\","\\AppData\\","\\ProgramData\\",
    "\\Users\\Public\\","\\Windows\\Temp\\","\\$Recycle")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
// Pivot B — sensor screenshot/clipboard telemetry if surfaced in DeviceEvents
let lookback = 14d;
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType in ("ScreenshotTaken","ClipboardData","GetClipboardData")
| project Timestamp, DeviceName, AccountName, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** Signed, sanctioned capture tools (SnippingTool, ShareX, Teams) writing to the user's Pictures/Screenshots folder; interactive parent (explorer.exe) session; user actively at console; single ad-hoc capture.
- **Suspicious indicators:** Script host (powershell/pwsh/wscript/mshta) or rundll32/regsvr32 invoking screen/clipboard APIs; images dropped in `\Temp\`, `\AppData\`, `\ProgramData\`, or `Public`; repeated/periodic captures; clipboard reads immediately after a credential prompt or RDP session.
- **Malicious confirmation:** Screenshot/clipboard collection followed by archiving (rar/7z/Compress-Archive) and outbound transfer; unsigned/renamed binary performing the capture; correlation with C2 network beacon or a known RAT SHA256; captures targeting a privileged user's session.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1113` (Screen Capture) and `Invoke-AtomicTest T1115` (Clipboard Data) — or manually run `Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::GetText()` and a `CopyFromScreen` screenshot script from PowerShell, writing the PNG into `%TEMP%`.
- **Expected hit:** The primary query returns the PowerShell process with `Get-Clipboard` / `CopyFromScreen` command lines; Pivot A returns the PNG created in `\Temp\` by powershell.exe.
- **If it does NOT fire:** check data-source ingestion, the time window, and any baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** Record host, user, initiating process lineage, and any image/staging artifacts. If DeviceEvents does not surface `ScreenshotTaken`/`ClipboardData` in your tenant, rely on the process/file telemetry paths (primary query + Pivot A) and file a visibility gap for the missing sensor coverage. Tune `benignImgTools` and the staging path list to your sanctioned toolset before promoting to an analytic rule.

## References

- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1115/