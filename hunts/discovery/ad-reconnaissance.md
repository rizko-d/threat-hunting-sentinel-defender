# Hunt Card — Active Directory Reconnaissance (BloodHound-style)

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-DI-001 |
| **ATT&CK Technique** | T1087 / T1069 / T1482 — Account, Group & Domain Trust Discovery |
| **Tactic** | Discovery |
| **Platform(s)** | Defender for Identity |
| **Data Source(s)** | `IdentityQueryEvents`, `IdentityDirectoryEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | Medium–High |

---

## 1. Trigger

Before lateral movement, adversaries map the domain (SharpHound/BloodHound,
`net group`, LDAP sweeps). Catching recon early is high-value — it's upstream of
the damage. Scheduled hunt and a purple-team validation target.

## 2. Hypothesis

> **If** an adversary enumerates Active Directory **in order to** find privilege
> escalation and lateral-movement paths, **then** I would observe a single
> principal issuing a burst of directory queries (SAMR/LDAP) enumerating users,
> groups, and trusts far beyond normal **in** `IdentityQueryEvents`,
> **distinguishable from normal by** the breadth (many distinct objects) and
> velocity of enumeration from one source in a short window.

**Negative result looks like:** No single source enumerated an abnormal breadth of
directory objects (users + groups + trusts) in a short burst during the window.

## 3. Scope

- **Time window:** last 14 days
- **Environment scope:** domain controllers monitored by Defender for Identity.
- **Known-good baseline:** IT admin tools, identity-governance scanners, and some
  security products enumerate the directory. Baseline by source and account.

## 4. Hunt Query

```kql
// AD recon: burst of directory enumeration queries from a single source.
let lookback = 14d;
let query_threshold = 30;         // distinct objects enumerated in a window
IdentityQueryEvents
| where Timestamp > ago(lookback)
| where ActionType in ("SAMR", "LDAP", "DNS")
| summarize
    DistinctTargets = dcount(QueryTarget),
    TargetSample = make_set(QueryTarget, 50),
    QueryCount = count(),
    Protocols = make_set(ActionType, 5)
    by AccountName, DeviceName, bin(Timestamp, 1h)
| where DistinctTargets >= query_threshold
| order by DistinctTargets desc
```

**Pivots / follow-up queries:**

```kql
// Correlate recon with a follow-on: did the same account then log on broadly?
IdentityLogonEvents
| where Timestamp > ago(14d)
| where AccountName =~ "<suspect_account>"
| summarize Hosts = dcount(DeviceName), HostSet = make_set(DeviceName, 50),
            LogonTypes = make_set(LogonType, 10)
    by AccountName
| where Hosts > 10
```

## 5. Triage Guidance

- **Benign indicators:** the source is a sanctioned admin workstation or identity-
  governance/security scanner running on a known schedule.
- **Suspicious indicators:** enumeration from a standard user workstation, a burst
  covering users *and* groups *and* trusts (BloodHound collection shape), off-hours
  timing.
- **Malicious confirmation:** recon is followed by targeted authentication to
  privileged accounts/hosts identified during enumeration.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is Defender for Identity deployed on all DCs?)
- [ ] Documented clear

**Notes:** Defender for Identity ships built-in recon alerts — a hunt hit that did
*not* fire a built-in alert is worth investigating (novel collection method or a
sensor gap). Cross-check `AlertInfo`.

---

## References

- https://attack.mitre.org/techniques/T1087/
- https://attack.mitre.org/techniques/T1482/
