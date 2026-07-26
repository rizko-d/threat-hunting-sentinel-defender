# Hunt Card — Malicious OAuth App Consent & Mailbox Exfiltration

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-CL-001 |
| **ATT&CK Technique** | T1098.003 / T1114 — Additional Cloud Roles / Email Collection |
| **Tactic** | Persistence / Collection / Exfiltration (cloud) |
| **Platform(s)** | Defender XDR (Cloud Apps) + Sentinel |
| **Data Source(s)** | `CloudAppEvents`, `AuditLogs`, `OfficeActivity` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High–Critical |

---

## 1. Trigger

Illicit OAuth consent grants and malicious inbox rules are the signature of
modern M365 account-takeover / BEC. Scheduled hunt; also triggered by any
phishing report or anomalous sign-in.

## 2. Hypothesis

> **If** an adversary grants consent to a malicious OAuth application (or creates
> a hidden inbox rule) **in order to** persist in and exfiltrate mail from a
> compromised M365 account, **then** I would observe an app-consent event granting
> high-risk mail/directory scopes, or a new-forwarding/delete rule, **in**
> `CloudAppEvents`/`AuditLogs`/`OfficeActivity`, **distinguishable from normal by**
> the sensitivity of the granted permissions and the concealment behavior of the
> rule (auto-forward external + move-to-deleted/RSS).

**Negative result looks like:** No OAuth consent grants to unverified apps
requesting `Mail.Read`/`Mail.ReadWrite`/`Directory.ReadWrite.All`, and no
external-auto-forward inbox rules created, in the window.

## 3. Scope

- **Time window:** last 30 days
- **Environment scope:** all M365 identities; prioritize privileged and exec
  mailboxes.
- **Known-good baseline:** sanctioned enterprise apps request broad scopes with
  admin consent. Baseline the approved app catalog.

## 4. Hunt Query

```kql
// Malicious inbox rule: external auto-forward + concealment (move/delete).
let lookback = 30d;
CloudAppEvents
| where Timestamp > ago(lookback)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| where Raw has_any ("DeleteMessage", "MoveToFolder", "Deleted Items", "RSS", "Junk")
| project Timestamp, AccountDisplayName, ActionType,
          Application, IPAddress, Raw
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// OAuth consent to apps requesting high-risk mail/directory scopes (Sentinel).
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application", "Add app role assignment grant to user")
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend Perms = tostring(TargetResources)
| where Perms has_any ("Mail.Read","Mail.ReadWrite","MailboxSettings","Directory.ReadWrite.All","full_access_as_app")
| project TimeGenerated, InitiatedBy, TargetApp, OperationName, Perms
| order by TimeGenerated desc
```

## 5. Triage Guidance

- **Benign indicators:** rule created by the mailbox owner for legitimate
  organization/forwarding to an internal address; app is in the sanctioned catalog
  with admin consent.
- **Suspicious indicators:** auto-forward to an *external* domain combined with
  move-to-deleted/RSS concealment; consent to an unverified app requesting broad
  mail scopes; grant from an anomalous IP shortly after a risky sign-in.
- **Malicious confirmation:** the forwarding target is attacker-controlled, the
  OAuth app has no business purpose, or mail is observed being read/exfiltrated
  via the app's token.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** MailSniper / a test OAuth app consent grant + a lab external-forward inbox rule
- **Expected hit:** the inbox-rule query fires on external ForwardTo + concealment, or the AuditLogs consent pivot on high-risk mail scopes.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is Unified Audit Log enabled? Cloud App connector on?)
- [ ] Documented clear

**Notes:** Two techniques, one hunt — they co-occur in real account-takeover.
Always pivot the flagged identity's recent `SigninLogs` for impossible travel /
risky sign-in that preceded the grant or rule creation.

---

## References

- https://attack.mitre.org/techniques/T1098/003/
- https://attack.mitre.org/techniques/T1114/
