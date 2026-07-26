# Triage & Documentation

Finding candidate rows is half the job. The other half is deciding what each
finding *means* and leaving a trail so the work is reproducible and auditable.

---

## The triage decision

Every surviving row from a hunt gets one of three verdicts:

| Verdict | Definition | Next action |
|---|---|---|
| **Benign** | Fully explained by legitimate activity | Document the known-good; add to baseline / exclusion so it doesn't resurface |
| **Suspicious** | Cannot yet be explained; not confirmed malicious | Escalate, pivot for more context, gather host/identity/network detail |
| **Malicious** | Confirmed adversary activity | Raise an incident; begin the IR process; preserve evidence |

The verdict is never "looks fine to me." It is a *decision backed by evidence*.

---

## The pivot checklist (context gathering)

When a finding needs more context, I pivot on the entity across every relevant
table. For a suspicious **device**:

- **Process tree** — `DeviceProcessEvents` around the event: parent, children,
  command lines.
- **Network** — `DeviceNetworkEvents`: what did it connect to, when, how often?
- **Logons** — `DeviceLogonEvents`: who logged on, from where, what type?
- **Files** — `DeviceFileEvents`: what was written/created, especially in
  startup/temp/system paths?
- **Registry** — `DeviceRegistryEvents`: autoruns, service installs, tampering.
- **Alerts** — `AlertInfo`/`AlertEvidence`: did anything already fire?

For a suspicious **identity** (Sentinel): `SigninLogs`,
`AADNonInteractiveUserSignInLogs`, `AuditLogs`, `IdentityLogonEvents` — where has
this account been active, from what IPs, with what result?

---

## Establishing "known-good"

Most hunts drown in false positives without a baseline. When I classify
something benign, I capture *why* so the next hunt doesn't re-litigate it:

- **Who** owns/runs it (team, service account, automation)?
- **What** signs it (publisher, cert thumbprint)?
- **Why** is it expected (business justification, change ticket)?
- **Where** does the exclusion belong (query filter, watchlist, baseline doc)?

A benign finding with no recorded justification is a finding I'll waste time on
again next month.

---

## Evidence standard

For every non-benign finding I record enough to reconstruct the hunt cold:

- The **exact KQL** that surfaced it (versioned in this repo).
- The **time window** queried.
- The **raw evidence** rows (entity names, timestamps, command lines) — or a
  reference to the exported results.
- The **reasoning** for the verdict.
- The **outcome** (incident ID, exclusion added, detection promoted, gap filed).

---

## When a hunt finds nothing

A clean hunt is a real, valuable result — but only if documented precisely:

- State the **hypothesis** and the **negative result** crisply: *"No account
  requested >10 distinct-SPN RC4 TGS tickets in the 30-day window across the
  monitored estate."*
- Note the **coverage**: which devices/identities were in scope, which were not.
- File any **visibility gaps** discovered (a table you needed that wasn't
  ingested, an audit policy that was off).
- Decide whether the hunt logic is precise enough to **promote to a detection**
  so this becomes continuous rather than point-in-time.

---

## From hunt to detection (graduation criteria)

I promote a hunting query into a scheduled analytic rule when:

1. It has run across several windows with a **manageable false-positive rate**.
2. The output maps cleanly to **alert entities** (account, host, IP, file).
3. There's a defined **response** for when it fires.
4. It fills a **coverage gap** (no existing detection for that TTP).

Until all four hold, it stays a hunt. Promoting a noisy query to a detection
just manufactures alert fatigue.

---

## The Hunt Card

Every hunt in this repo is documented on a **Hunt Card**
([../templates/hunt-card.md](../templates/hunt-card.md)) capturing: trigger,
hypothesis, ATT&CK mapping, data sources, queries, findings, verdict, and
outcome. The card is the durable artifact — the query is just one field on it.
