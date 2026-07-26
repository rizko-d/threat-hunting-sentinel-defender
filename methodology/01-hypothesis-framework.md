# Hypothesis Framework

A hunt is only as good as its hypothesis. This is how I build one that is
specific, falsifiable, and directly translatable into KQL.

---

## The anatomy of a hunting hypothesis

Every hypothesis I write fills this template:

> **If** an adversary performs `<TTP>`
> **in order to** `<objective>`,
> **then** I would observe `<observable>`
> **in** `<data source / table>`,
> **distinguishable from normal by** `<discriminator>`.

Worked example:

> **If** an adversary performs Kerberoasting (T1558.003)
> **in order to** obtain crackable service-account credentials,
> **then** I would observe a single account requesting many Kerberos service
> tickets (TGS) with weak encryption (RC4/0x17) in a short window
> **in** `SecurityEvent` (Event ID 4769) / `IdentityLogonEvents`,
> **distinguishable from normal by** the volume of distinct SPNs requested per
> account and the encryption downgrade to RC4.

That single sentence tells me the table, the field, the anomaly, and the
false-positive discriminator. From there the KQL nearly writes itself.

---

## Three sources of hypotheses

### 1. Intelligence-driven (top-down)

Start from a threat report or ATT&CK technique. "Group X uses AS-REP roasting
and DCSync." Map each named TTP to an observable and hunt it. This is the most
common driver and the easiest to justify.

**Strength:** grounded in real adversary behavior.
**Weakness:** you only find what you already know to look for.

### 2. Anomaly-driven (bottom-up)

Start from the data. Baseline normal, then look for outliers — rare parent-child
process pairs, first-time-seen binaries, unusual logon times, new outbound
destinations. Let the anomaly suggest the technique.

**Strength:** can surface novel/unknown TTPs.
**Weakness:** noisy; requires a solid baseline and patience.

### 3. Crown-jewel-driven (situational awareness)

Start from what matters. Enumerate the crown jewels (domain controllers,
identity providers, source-control, secrets vaults) and ask: "What would
compromise of *this* look like in my logs?" Work backward from impact to
observable.

**Strength:** aligns hunting effort with business risk.
**Weakness:** can miss attacks on lower-value stepping-stones.

---

## Making a hypothesis falsifiable

A hypothesis I cannot disprove is useless. I make each one falsifiable by
defining, up front, **what a negative result looks like**:

- *"Zero accounts requested more than N distinct-SPN TGS tickets with RC4 in the
  last 7 days"* — a clean, defensible negative.
- Not: *"I didn't really see anything obviously bad"* — unfalsifiable, worthless.

If I can't state the negative result crisply, the hypothesis is too vague. I
sharpen it until I can.

---

## From hypothesis to ATT&CK mapping

Each hypothesis maps to at least one ATT&CK technique. This does two jobs:

1. It plugs the hunt into **coverage tracking** — over time I can see which
   tactics/techniques I've hunted and where the blind spots are (see
   [../mapping/attack-coverage.md](../mapping/attack-coverage.md)).
2. It anchors the hunt to a **known behavior**, so triage has a reference for
   what "malicious" looks like.

---

## Scoring hypotheses (what to hunt first)

I have more hypothesis ideas than time. I prioritize with a simple score:

| Factor | Low (1) | High (3) |
|---|---|---|
| **Threat relevance** | Generic | Active against my sector/stack |
| **Impact if true** | Nuisance | Crown-jewel compromise |
| **Data availability** | No/partial logs | Full fidelity available |
| **Detection gap** | Already alerted on | No existing detection |

`Priority = ThreatRelevance + Impact + DataAvailability + DetectionGap`

I hunt the highest-scoring hypotheses first. A high-impact, high-relevance TTP
with good data and no existing detection is the sweet spot — that's where a hunt
delivers the most value.

---

## Anti-patterns

- **The boil-the-ocean hunt.** "Find all malware." Not a hypothesis. Scope it.
- **The tautology.** A hypothesis whose observable is guaranteed to be present
  (or absent) regardless of adversary activity. Tests nothing.
- **The un-baselined anomaly.** "Anything weird." Without a definition of normal,
  everything looks weird and nothing is actionable.
- **The data-blind hypothesis.** A beautiful theory with no log source to test
  it. That's a visibility gap to file, not a hunt to run — yet.
