# Kill-Chain Hunt Chaining — A Correlated Intrusion Story

Individual Hunt Cards find individual behaviors. Real intrusions are *sequences*.
This playbook shows how the hunts in this library chain together into a single
correlated investigation — how a hit on one hunt should make you pivot to the
next, reconstructing the adversary's path from initial access to impact.

The value of a hunt library is not 18 isolated queries; it is the ability to
walk an intrusion end-to-end. A lone "obfuscated PowerShell" hit is a lead. That
same hit, traced back to a phishing email and forward to a ransomware payload, is
an incident narrative you can act on and report.

---

## The chain at a glance

```
  INITIAL ACCESS            EXECUTION / PRIV-ESC          ACTIONS ON OBJECTIVE
  ──────────────            ────────────────────          ────────────────────
  TH-IA-001  phishing  ──►  TH-IA-003  user exec   ──►  TH-CA-002  LSASS dump
  (delivered mail)          (Office → shell)             (creds harvested)
       │                         │                              │
       │                    TH-EX-001  obfuscated PS            │
       │                    (encoded loader)                    ▼
  TH-IA-002  web exploit        │                        TH-DI-001  AD recon
  (w3wp → shell)                ▼                         (map the domain)
       │                   TH-PR-001  UAC bypass                │
       │                   TH-PR-002  token theft               ▼
       ▼                   TH-PR-003  DLL hijack          TH-LM-001  WMI lateral
  TH-IA-002 web shell      (SYSTEM integrity)             (pivot to next host)
  on disk                       │                              │
                                ▼                              ▼
                          TH-PE-001  scheduled task      TH-C2-001  beaconing
                          (persistence)                  (C2 channel established)
                                                               │
                                                               ▼
                                                         TH-XF-*  exfiltration
                                                         TH-CO-*  collection
                                                               │
                                                               ▼
                                          TH-IM-003 → TH-IM-001 → TH-IM-002
                                          (service stop → shadow del → encrypt)
                                          TH-DE-001  log clearing (anti-forensics)
```

---

## Story 1 — Phishing to ransomware (the classic affiliate playbook)

The single most common intrusion shape today. Trace it hunt-by-hunt:

1. **TH-IA-001 (Phishing Delivery)** — a message with an ISO/LNK attachment is
   *delivered* (not blocked) to a finance user. → Pivot forward: did they open it?
2. **TH-IA-003 (User Execution)** — `outlook.exe`/`explorer.exe` spawns a script
   host from the mounted ISO. The click became execution. → Pivot to the payload.
3. **TH-EX-001 (Obfuscated PowerShell)** — an encoded loader runs, pulling the
   next stage. → Pivot to what it drops and where it calls.
4. **TH-C2-001 (C2 Beaconing)** — the host starts regular check-ins to a young
   domain. Command-and-control is live. → Pivot to privilege and credentials.
5. **TH-CA-002 (LSASS Dumping)** — operator dumps LSASS for credentials. →
   Pivot to recon and movement.
6. **TH-DI-001 (AD Recon)** → **TH-LM-001 (WMI Lateral Movement)** — map the
   domain, pivot to a file server / the DC.
7. **TH-IM-003 → TH-IM-001 → TH-IM-002** — stop security/backup/DB services,
   delete shadow copies, mass-encrypt. Impact.
8. **TH-DE-001 (Log Clearing)** — clear the Security log to slow the responders.

**Hunting takeaway:** catching *any* link in this chain should trigger pivots in
BOTH directions. The earlier you catch it (stage 1–4), the cheaper the response.
A single-hunt hit is never "one weird process" — it's a position in a chain, and
your job is to find the rest of the chain.

---

## Story 2 — Public-facing exploit to hands-on-keyboard

1. **TH-IA-002 (Public-Facing App Exploit)** — `w3wp.exe` spawns `cmd.exe /c
   whoami`; a small `.aspx` appears in `wwwroot`. A web shell is planted. → Pivot:
   what does the web-server context do next?
2. **TH-PR-002 / TH-PR-003 (Token Theft / DLL Hijack)** — escalate from the
   web-service account to SYSTEM. → Pivot to persistence + credentials.
3. **TH-PE-001 (Scheduled Task)** — durable persistence installed.
4. **TH-CA-001 (Kerberoasting)** — request service tickets to crack offline. →
   Pivot to lateral movement with the cracked account.
5. **TH-LM-001 (WMI Lateral Movement)** → onward to crown jewels.

**Hunting takeaway:** a web-process-spawns-shell hit (TH-IA-002) is one of the
highest-fidelity signals in the library — treat it as an active intrusion until
disproven, and immediately sweep the same host for the escalation/persistence
hunts above.

---

## How to pivot: the universal rules

Whenever a hunt fires, run these pivots before closing it out:

| Pivot direction | Question | Hunts / tables to check |
|---|---|---|
| **Backward (how did they get here?)** | What preceded this on the host/identity? | TH-IA-*, EmailEvents, DeviceProcessEvents parent chain |
| **Forward (what did they do next?)** | What ran/connected after? | TH-C2-001, TH-CA-*, TH-LM-001 |
| **Lateral (where else?)** | Same tooling/IOC on other hosts? | Stack the SHA256/RemoteIP/task-name across the estate |
| **Identity (who?)** | Where else has this account been? | SigninLogs, IdentityLogonEvents, DeviceLogonEvents |

The [methodology triage guide](../methodology/03-triage-and-documentation.md)
covers the entity-pivot checklist in detail. This doc is about *sequencing* those
pivots into an intrusion narrative.

---

## From chain to detection

When a full chain is reconstructed, the highest-value outcome is a **correlated
analytic rule** that fires on the *sequence*, not just one step — e.g. "delivered
dangerous attachment → same host spawns encoded PowerShell within 1 hour." A
sequence detection has a far lower false-positive rate than any single step,
because benign activity rarely reproduces the whole chain. See the
[hunt→detection graduation criteria](../methodology/03-triage-and-documentation.md).
