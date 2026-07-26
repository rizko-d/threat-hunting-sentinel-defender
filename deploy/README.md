# Deploy Hunts to Microsoft Sentinel

Turn the Hunt Cards in this library from copy-paste queries into **deployed
Sentinel artifacts** — Scheduled Analytic Rules (for hunts precise enough to
alert) or saved Hunting Queries (for exploratory hunts you run on demand).

This directory gives you two paths:

| File | What it does |
|---|---|
| `scheduled-query-rule.template.json` | ARM template for one Sentinel Scheduled Query Rule (an analytic detection) |
| `hunting-query.template.json` | ARM template for one Sentinel saved Hunting Query |
| `Deploy-Hunts.ps1` | PowerShell that reads a hunt's KQL and deploys it via the template |

> Deployment target is **Microsoft Sentinel** (Log Analytics workspace). Defender
> XDR Advanced Hunting queries run interactively at `security.microsoft.com`; the
> `Device*` tables are also queryable from Sentinel when the Microsoft 365
> Defender connector streams them into the workspace.

---

## Prerequisites

- Azure PowerShell (`Az` module): `Install-Module Az -Scope CurrentUser`
- `Connect-AzAccount` with rights on the target subscription
- A Microsoft Sentinel-enabled Log Analytics workspace
- Role: **Microsoft Sentinel Contributor** (or Contributor) on the workspace RG

---

## Quick start

```powershell
# 1. Authenticate
Connect-AzAccount
Select-AzSubscription -SubscriptionId "<sub-id>"

# 2. Deploy a single hunt as a scheduled analytic rule
./Deploy-Hunts.ps1 `
  -ResourceGroup   "rg-sentinel" `
  -WorkspaceName   "law-sentinel" `
  -HuntCardPath    "../hunts/impact/shadow-copy-deletion.md" `
  -Mode            ScheduledRule

# 3. Or deploy every hunt in a tactic folder as saved hunting queries
./Deploy-Hunts.ps1 `
  -ResourceGroup   "rg-sentinel" `
  -WorkspaceName   "law-sentinel" `
  -HuntCardPath    "../hunts/credential-access" `
  -Mode            HuntingQuery
```

The script extracts the **first ```kql block** (the primary query) and the MITRE
metadata from each Hunt Card, then deploys it. Pivot/follow-up queries are left in
the card for interactive use.

---

## What gets deployed

### ScheduledRule mode

A Sentinel **Scheduled Query Rule** — a real analytic detection that runs on a
cadence and raises incidents. Defaults (override in the script/template):

- **Frequency:** every 1 hour (`PT1H`)
- **Period:** last 1 day (`P1D`)
- **Trigger:** results > 0
- **Severity:** taken from the Hunt Card's "Severity if confirmed"
- **Tactics / techniques:** mapped from the card's ATT&CK metadata

> Only promote hunts to scheduled rules once they've been validated and tuned to a
> manageable false-positive rate (see the card's Validation section and the
> [triage/graduation guide](../methodology/03-triage-and-documentation.md)).
> Deploying a noisy hunt as an always-on rule manufactures alert fatigue.

### HuntingQuery mode

A saved **Hunting Query** that shows up under Sentinel → Hunting. It does not
alert — it's there for analysts to run on demand. This is the right mode for
exploratory, wide-net hunts that are too broad to be detections.

---

## Idempotency & safety

- Rules/queries are named from the Hunt ID (e.g. `TH-IM-001`), so re-running the
  script **updates** rather than duplicates.
- The script does a `-WhatIf` dry run when you pass `-DryRun`, printing what it
  would deploy without touching the workspace.
- Nothing is deleted automatically. Remove artifacts via the Sentinel portal or
  `Remove-AzSentinelAlertRule`.

---

## Manual / portal alternative

Prefer clicking? Every hunt is copy-paste ready:

1. **Analytic rule:** Sentinel → Analytics → Create → Scheduled query rule →
   paste the primary KQL → set the ATT&CK mapping from the card → set frequency.
2. **Hunting query:** Sentinel → Hunting → New Query → paste → tag the technique.

The ARM templates here just codify those same choices as infrastructure-as-code so
your detection content is version-controlled alongside the hunts.
