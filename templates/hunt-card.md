# Hunt Card — <Hunt Title>

> Copy this file into `hunts/<tactic>/<hunt-name>.md` and fill it in. Every hunt
> in this repo carries a card so the work is reproducible and auditable.

---

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-<tactic>-<nnn> |
| **ATT&CK Technique** | T#### / T####.### — <name> |
| **Tactic** | <tactic> |
| **Platform(s)** | Defender XDR / Sentinel / both |
| **Data Source(s)** | `<table1>`, `<table2>` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | YYYY-MM-DD |
| **Severity if confirmed** | Low / Medium / High / Critical |

---

## 1. Trigger

Why this hunt, right now? (CTI report, KEV entry, red team exercise, anomaly,
crown-jewel review, scheduled cadence.)

## 2. Hypothesis

> **If** an adversary performs `<TTP>` **in order to** `<objective>`, **then** I
> would observe `<observable>` **in** `<table>`, **distinguishable from normal
> by** `<discriminator>`.

**Negative result looks like:** <the crisp, falsifiable "clean" statement>

## 3. Scope

- **Time window:** <e.g. last 30 days>
- **Environment scope:** <all devices / segment / identity>
- **Known-good baseline:** <what normal looks like; expected exclusions>

## 4. Hunt Query

```kql
<primary KQL here>
```

**Pivots / follow-up queries:**

```kql
<pivot query — process tree, network, logons, etc.>
```

## 5. Triage Guidance

- **Benign indicators:** <what explains this away>
- **Suspicious indicators:** <what raises the stakes>
- **Malicious confirmation:** <what proves it>

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed
- [ ] Documented clear

**Notes:** <findings summary, false-positive sources, tuning notes>

---

## References

- <ATT&CK URL>
- <CTI / blog / advisory>
