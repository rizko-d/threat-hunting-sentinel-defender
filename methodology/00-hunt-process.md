# Threat Hunting Process

How I run a structured hunt in Microsoft Sentinel and Microsoft Defender XDR
(Advanced Hunting). This is the repeatable loop I follow for every hunt — from
an initial idea to a documented, testable outcome that either produces a
detection, an incident, or a defensible "clear" result.

Threat hunting is **hypothesis-driven, assume-breach** analysis. I am not
waiting for an alert to fire. I start from the premise that an adversary may
already be inside, and I go looking for the evidence they would have left
behind.

---

## The Loop (PEAK-aligned)

I follow a variant of the PEAK framework (Prepare, Execute, Act with Knowledge).
Every hunt moves through six phases:

```
   ┌──────────────┐
   │ 1. Trigger   │  New CTI, KEV entry, red team report, anomaly, or scheduled hunt
   └──────┬───────┘
          v
   ┌──────────────┐
   │ 2. Hypothesis│  "If <adversary> did <TTP>, I would see <observable> in <table>"
   └──────┬───────┘
          v
   ┌──────────────┐
   │ 3. Scope     │  Data sources, time window, environment boundaries, ATT&CK mapping
   └──────┬───────┘
          v
   ┌──────────────┐
   │ 4. Hunt      │  Run KQL, pivot, refine, reduce false positives
   └──────┬───────┘
          v
   ┌──────────────┐
   │ 5. Triage    │  Benign? Malicious? Unknown? Document evidence for each finding
   └──────┬───────┘
          v
   ┌──────────────┐
   │ 6. Outcome   │  Detection rule, incident, gap in visibility, or documented "clear"
   └──────────────┘
```

Every hunt produces one of four outcomes. **A hunt that finds nothing is not a
failure** — it is a documented statement about what an adversary was *not* doing
in a given window, plus (usually) a new detection or a visibility gap to close.

---

## Phase 1 — Trigger

A hunt starts for a reason. I track the trigger because it justifies the time
spent and shapes the hypothesis.

| Trigger type | Example | Where it comes from |
|---|---|---|
| **Threat intelligence** | New TTP report on a ransomware affiliate | Vendor blogs, MISP, ISAC |
| **KEV / zero-day** | CISA adds an actively-exploited CVE | CISA KEV feed, MSRC |
| **Red team / purple team** | "We ran Rubeus last sprint — did we catch it?" | Internal exercise report |
| **Anomaly** | Unexpected spike in a table, odd parent-child process | Sentinel workbook, gut feel |
| **Crown-jewel driven** | "What would compromise of the DC look like?" | Asset criticality review |
| **Scheduled** | Monthly recurring hunt across the top-10 TTPs | Hunt program cadence |

---

## Phase 2 — Hypothesis

The hypothesis is the single most important artifact. A good hypothesis is
**specific, falsifiable, and mapped to an observable**. See
[01-hypothesis-framework.md](01-hypothesis-framework.md).

Bad hypothesis: *"Look for lateral movement."*
Good hypothesis: *"If an adversary is moving laterally via WMI, I will see
`wmiprvse.exe` spawning `cmd.exe`/`powershell.exe` on a remote host within
seconds of a network logon (Type 3) from a workstation subnet, in
`DeviceProcessEvents` correlated with `DeviceLogonEvents`."*

The second one tells me exactly which table to query, what to look for, and how
to know if I found it.

---

## Phase 3 — Scope

Before I write KQL I define the boundaries:

- **Data sources** — which Sentinel tables or Defender XDR schemas hold the
  observable? (See [../docs/data-sources.md](../docs/data-sources.md).)
- **Time window** — how far back? Dwell time for the threat class matters:
  commodity malware is hours/days, APT is weeks/months.
- **Environment scope** — all devices, or just a segment (DMZ, PCI, servers)?
- **ATT&CK mapping** — technique ID(s) so the hunt slots into coverage tracking.
- **Known-good baseline** — what does normal look like here? Without a baseline
  every hunt drowns in false positives.

---

## Phase 4 — Hunt

Run the query. Then pivot. The first query almost never lands — hunting is
iterative refinement:

1. **Cast wide, then narrow.** Start broad to see the shape of the data, then
   add filters to cut noise without cutting the signal.
2. **Pivot on entities.** A hit on one device → pivot to that device's process
   tree, network connections, logons, and file writes in the same window.
3. **Stack and cluster.** `summarize count() by ...` to find rare values
   (long-tail analysis / "least frequency of occurrence"). Rare is interesting.
4. **Reduce false positives at the query level**, not by eyeballing 5,000 rows.
   Exclude known-good signers, expected admin tools, sanctioned automation.

See [02-kql-hunting-techniques.md](02-kql-hunting-techniques.md) for the KQL
patterns I use most (long-tail analysis, joins, time-series, `mv-expand`).

---

## Phase 5 — Triage

Every surviving row gets classified:

| Verdict | Meaning | Action |
|---|---|---|
| **Benign** | Explained by legitimate activity | Document the known-good, add to baseline/exclusion |
| **Malicious** | Confirmed adversary activity | Raise an incident, begin IR |
| **Suspicious** | Can't explain it yet | Escalate, gather more context, keep pivoting |

I record evidence for the verdict — not just "benign", but *why*: the signer,
the parent process, the business justification, the ticket number.

---

## Phase 6 — Outcome

A hunt is not done until it produces a durable artifact:

- **New detection** — if the hunt logic is precise enough, promote it to a
  scheduled analytic rule. (This repo's sibling library holds those:
  detection rules live in the SIEM; hunts live here.)
- **Incident** — if malicious, hand off to IR with the evidence trail.
- **Visibility gap** — if I *couldn't* run the hunt because the data wasn't
  there, that's a finding: log source to onboard, audit policy to enable.
- **Documented clear** — findings summary, queries used, time window, and
  "nothing malicious observed" with the evidence to back it.

Every hunt in this repo carries a **Hunt Card** (see
[../templates/hunt-card.md](../templates/hunt-card.md)) capturing all six phases
so the work is reproducible and auditable.

---

## Sentinel vs Defender XDR — where I hunt what

| | Microsoft Sentinel | Microsoft Defender XDR (Advanced Hunting) |
|---|---|---|
| **Scope** | Whole estate: identity, cloud, network, custom logs | Endpoints, email, identity, cloud apps (M365) |
| **Query surface** | Log Analytics — all ingested tables | Fixed XDR schema (`Device*`, `Email*`, `Identity*`, `Cloud*`) |
| **Retention** | Configurable (up to years w/ archive) | 30 days hot (Advanced Hunting) |
| **Best for** | Cross-source correlation, long-window APT hunts | Deep endpoint/email detail, near-real-time |
| **Language** | KQL | KQL (subset of tables) |

Many hunts run in **both**: I find the endpoint behavior in Defender XDR, then
correlate it against identity and network in Sentinel. When Defender data is
streamed into Sentinel (via the Microsoft 365 Defender connector), the same
`Device*` tables are queryable from the Sentinel workspace too.
