# Hunt Card — DLL Search-Order & Phantom DLL Hijacking

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-PR-003 |
| **ATT&CK Technique** | T1574.001 / T1574.002 — Hijack Execution Flow: DLL Search-Order / DLL Side-Loading |
| **Tactic** | Privilege Escalation / Persistence / Defense Evasion |
| **Platform(s)** | Defender XDR |
| **Data Source(s)** | `DeviceImageLoadEvents`, `DeviceFileEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

DLL hijacking lets an attacker get their code loaded by a trusted, often
auto-elevated or signed, process — escalating privilege, persisting, and evading
defenses in one move. Side-loading against signed vendor binaries is a hallmark of
APT and modern loaders. Scheduled hunt; triggered by any lead involving a signed
process behaving oddly.

## 2. Hypothesis

> **If** an adversary hijacks DLL search order or side-loads a malicious DLL **in
> order to** execute code inside a trusted/elevated process, **then** I would
> observe a signed executable loading an *unsigned* or *user-writable-path* DLL
> whose name matches a system/known DLL but resides in the application's own
> directory or a temp/user path, **in** `DeviceImageLoadEvents`, **distinguishable
> from normal by** the DLL being unsigned, recently written, and loaded from a
> non-system directory.

**Negative result looks like:** No signed process loaded an unsigned DLL from a
user-writable/temp/application-local path where a system copy would normally be
expected, across the estate in the window.

## 3. Scope

- **Time window:** last 14 days
- **Environment scope:** all endpoints; prioritize hosts running third-party
  signed software (common side-load targets).
- **Known-good baseline:** applications legitimately load their own DLLs from their
  install dir. The discriminators are *unsigned* + *recently written* +
  *system-DLL name in a non-system path*.

## 4. Hunt Query

```kql
// DLL side-loading: signed process loads an unsigned DLL from a non-system path.
let lookback = 14d;
let system_paths = dynamic([@"c:\windows\system32\", @"c:\windows\syswow64\", @"c:\windows\winsxs\"]);
DeviceImageLoadEvents
| where Timestamp > ago(lookback)
| where FileName endswith ".dll"
| extend LoadPath = tolower(FolderPath)
// unsigned / invalid-signature DLLs only
| where InitiatingProcessFileName != "" 
| where isnotempty(SHA256)
| where not(LoadPath has_any (system_paths))          // loaded from outside system dirs
| where FileName in~ (
    // commonly-abused system DLL names dropped into app/user dirs
    "version.dll","dbghelp.dll","wininet.dll","secur32.dll","userenv.dll",
    "profapi.dll","cryptsp.dll","dwmapi.dll","winhttp.dll","vcruntime140.dll",
    "textinputframework.dll","edgegdi.dll","msasn1.dll"
  )
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          FileName, FolderPath, SHA256
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Correlate: was that DLL recently WRITTEN to the app dir (the plant) before load?
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where FileName endswith ".dll"
| where FolderPath !startswith @"C:\Windows\"
| where InitiatingProcessFileName !in~ ("msiexec.exe","TrustedInstaller.exe","TiWorker.exe","setup.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, FolderPath, SHA256
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** the DLL is signed by the same vendor as the loading app
  and lives in its legitimate install directory; an installer (`msiexec`,
  TrustedInstaller) placed it as part of a signed package.
- **Suspicious indicators:** an unsigned DLL with a system-DLL name loaded from a
  user/temp/app-local path, written recently by a non-installer process, loaded by
  a signed vendor binary (classic side-load).
- **Malicious confirmation:** the loaded DLL exhibits malicious behavior (network
  beacon, injection, credential access) or the plant+load sequence is tied to an
  attacker-controlled drop.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** `Invoke-AtomicTest T1574.001` / T1574.002 (side-load an unsigned DLL next to a signed binary)
- **Expected hit:** the signed process loads an unsigned DLL from a non-system path, correlated with the recent DLL-write pivot.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is image-load telemetry / signature info populated?)
- [ ] Documented clear

**Notes:** The two-query correlation — *DLL written by a non-installer* (plant)
then *loaded by a signed process from a non-system path* (execution) — is far
higher-confidence than either alone. Maintain and tune the abused-DLL-name list to
your environment; attackers rotate targets, so the *unsigned + non-system-path +
system-name* logic matters more than any fixed list.

---

## References

- https://attack.mitre.org/techniques/T1574/001/
- https://attack.mitre.org/techniques/T1574/002/
- HijackLibs — catalog of DLL hijacking/side-loading targets
