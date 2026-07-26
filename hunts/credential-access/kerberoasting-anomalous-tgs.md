# Hunt Card — Kerberoasting via Anomalous TGS Requests

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-CA-001 |
| **ATT&CK Technique** | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| **Tactic** | Credential Access |
| **Platform(s)** | Sentinel + Defender for Identity |
| **Data Source(s)** | `SecurityEvent` (4769), `IdentityLogonEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

Kerberoasting is a top-tier credential-access technique used by nearly every
ransomware affiliate and red team. Scheduled monthly hunt against AD identity
telemetry; also triggered whenever a purple-team exercise runs Rubeus/GetUserSPNs.

## 2. Hypothesis

> **If** an adversary performs Kerberoasting **in order to** obtain crackable
> service-account credentials, **then** I would observe a single account
> requesting Kerberos service tickets (TGS) for many distinct SPNs with weak RC4
> encryption in a short window **in** `SecurityEvent` Event ID 4769, 
> **distinguishable from normal by** the volume of distinct service names per
> account and the RC4 (0x17) encryption downgrade.

**Negative result looks like:** No account requested TGS tickets for more than 10
distinct SPNs with RC4 encryption within any 1-hour window over the 30-day scope.

## 3. Scope

- **Time window:** last 30 days
- **Environment scope:** all domain-joined systems reporting 4769 to Sentinel
- **Known-good baseline:** vulnerability scanners and some legacy apps enumerate
  SPNs; SCCM and certain service accounts request many tickets legitimately —
  baseline and exclude by account.

## 4. Hunt Query

```kql
// Kerberoasting: accounts requesting many distinct SPNs with RC4 (0x17) TGS.
let lookback = 30d;
let rc4_ticket = "0x17";           // RC4-HMAC — the roastable, downgradeable cipher
let distinct_spn_threshold = 10;   // tune to your environment baseline
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4769                          // Kerberos service ticket requested
| where TicketEncryptionType == rc4_ticket       // weak encryption
| where ServiceName !endswith "$"                // exclude machine accounts
| where TargetUserName !endswith "$"
| where Status == "0x0"                          // successful issuance
| summarize
    DistinctSPNs = dcount(ServiceName),
    SPNSet = make_set(ServiceName, 50),
    TicketCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SourceIPs = make_set(IpAddress, 20)
    by TargetUserName, bin(TimeGenerated, 1h)
| where DistinctSPNs >= distinct_spn_threshold
| order by DistinctSPNs desc
```

**Pivots / follow-up queries:**

```kql
// Pivot: what did the requesting identity do next? Correlate with logons.
IdentityLogonEvents
| where Timestamp > ago(30d)
| where AccountName =~ "<suspect_account>"
| project Timestamp, DeviceName, LogonType, IPAddress, Application, ActionType
| order by Timestamp asc
```

## 5. Triage Guidance

- **Benign indicators:** the source is a known vulnerability scanner or
  SPN-enumeration tool on a scheduled window; the account is a monitoring/SCCM
  identity with a documented reason to request many tickets.
- **Suspicious indicators:** requests originate from a workstation (not a
  server/scanner), the account has no business reason to touch many SPNs, RC4 is
  requested despite AES being available domain-wide.
- **Malicious confirmation:** the same host subsequently shows credential-cracking
  tooling, offline ticket export, or the roasted service account authenticates
  from a new host shortly after.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is 4769 auditing enabled on all DCs?)
- [ ] Documented clear

**Notes:** The strongest signal is RC4 *when AES is available* — an encryption
downgrade is adversary tradecraft. If your DCs are AES-only, RC4 4769s are
inherently suspicious.

---

## References

- https://attack.mitre.org/techniques/T1558/003/
- Windows Security Event ID 4769 (Kerberos service ticket request)
