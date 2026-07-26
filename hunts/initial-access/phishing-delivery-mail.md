# Hunt Card — Phishing Delivery via Malicious Mail

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-IA-001 |
| **ATT&CK Technique** | T1566.001 / T1566.002 — Phishing: Attachment / Link |
| **Tactic** | Initial Access |
| **Platform(s)** | Defender XDR (Office 365) |
| **Data Source(s)** | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

Phishing is the #1 initial-access vector. Even with a mail gateway, dangerous
messages get delivered — the hunt looks for what *landed in the inbox*, not just
what was blocked. Scheduled daily hunt; also triggered by any user-reported
phish or a downstream endpoint lead that needs an entry-point.

## 2. Hypothesis

> **If** an adversary delivers phishing **in order to** gain initial access, **then**
> I would observe delivered (not blocked) messages carrying executable/script/archive
> attachments or links to newly-registered/rare domains, often with sender-spoofing
> or authentication failures, **in** `EmailEvents`/`EmailAttachmentInfo`/`EmailUrlInfo`,
> **distinguishable from normal by** the dangerous file type or hostile URL reaching
> the inbox combined with failed SPF/DKIM/DMARC or lookalike sender domains.

**Negative result looks like:** No message with a high-risk attachment type or a
link to a young/rare domain was *delivered to inbox* (DeliveryAction == Delivered)
with authentication failures across the tenant in the window.

## 3. Scope

- **Time window:** last 7 days
- **Environment scope:** all mailboxes; prioritize exec/finance/privileged users
  (BEC and spearphish targets).
- **Known-good baseline:** business partners send archives/links legitimately.
  Baseline trusted sender domains and expected file types per team.

## 4. Hunt Query

```kql
// Delivered phishing: dangerous attachments reaching the inbox.
let lookback = 7d;
let dangerous_ext = dynamic([
    "exe","scr","js","jse","vbs","vbe","wsf","hta","lnk","iso","img","vhd",
    "ps1","bat","cmd","jar","one","msi","cpl","chm","xll"
]);
EmailEvents
| where Timestamp > ago(lookback)
| where DeliveryAction == "Delivered"                 // it reached the user
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp > ago(lookback)
    | extend Ext = tolower(tostring(split(FileName, ".")[-1]))
    | where Ext in (dangerous_ext)
  ) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress,
          Subject, FileName, Ext, FileType, SHA256,
          AuthenticationDetails, EmailDirection
| order by Timestamp desc
```

**Pivots / follow-up queries:**

```kql
// Link-based phish: delivered mail with URLs to rare/young domains + auth failures.
let lookback = 7d;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where AuthenticationDetails has_any ("SPF: fail", "DKIM: fail", "DMARC: fail", "CompAuth: fail")
| join kind=inner (EmailUrlInfo | where Timestamp > ago(lookback)) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderMailFromDomain,
          RecipientEmailAddress, Subject, Url, UrlDomain, AuthenticationDetails
| order by Timestamp desc
```

## 5. Triage Guidance

- **Benign indicators:** the sender is an established, authenticated business
  partner; the file type is expected for that relationship; the URL points to a
  known-good SaaS domain.
- **Suspicious indicators:** ISO/LNK/HTA/script attachments, links to
  newly-registered or lookalike domains, SPF/DKIM/DMARC failures, display-name
  spoofing of an internal exec, urgency/payment lures.
- **Malicious confirmation:** the recipient opened the attachment/clicked the link
  and the endpoint shows follow-on execution (correlate TH-IA-003 / TH-EX-001).

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** a lab phish send (GoPhish / manual) with an ISO/LNK/HTA attachment or a link to a rare test domain
- **Expected hit:** the delivered message with a dangerous attachment or auth-fail + rare-domain URL surfaces in `EmailEvents`.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised (+ purge delivered message tenant-wide)
- [ ] Visibility gap filed (is the Defender for Office 365 connector on?)
- [ ] Documented clear

**Notes:** The pivot that matters most — join delivered phish to endpoint
execution. A delivered ISO nobody opened is a tuning note; a delivered ISO that
spawned `powershell.exe` is an active intrusion. Always chase the click-through.
Remediate by purging the message from all mailboxes, not just the reporter's.

---

## References

- https://attack.mitre.org/techniques/T1566/001/
- https://attack.mitre.org/techniques/T1566/002/
