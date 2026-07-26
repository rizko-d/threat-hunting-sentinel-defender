# Hunt Card — Exfiltration Over Alternative Protocol (DNS / Non-Standard Port)

## Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-XF-003 |
| **ATT&CK Technique** | T1048 / T1048.003 — Exfiltration Over Alternative / Unencrypted Non-C2 Protocol |
| **Tactic** | Exfiltration |
| **Platform(s)** | Defender XDR + Sentinel |
| **Data Source(s)** | `DnsEvents`, `DeviceNetworkEvents` |
| **Author** | Rizko Febri Rachmayadi |
| **Date** | 2026-07-26 |
| **Severity if confirmed** | High |

---

## 1. Trigger

When web egress is filtered, adversaries fall back to protocols the perimeter
trusts — DNS being the classic. Data is encoded into long, high-entropy
subdomains and drip-fed as queries, or bulk-transferred over a non-standard port.
Scheduled daily hunt; also triggered by CTI on tunneling tooling (iodine,
dnscat2, DNSExfiltrator).

## 2. Hypothesis

> **If** an adversary tunnels data out over DNS (or bulk-transfers over a
> non-standard port) **in order to** bypass web-proxy egress controls, **then** I
> would observe a host generating an anomalously high volume of DNS queries with
> long, high-entropy subdomains to one parent domain — or a large outbound
> transfer on an unusual port — **in** `DnsEvents` / `DeviceNetworkEvents`,
> **distinguishable from normal by** query volume per host↔domain, subdomain
> length, and character entropy far above normal FQDN patterns.

**Negative result looks like:** No host↔parent-domain pair exceeded the query-count,
mean-subdomain-length, and entropy thresholds, and no large bulk transfer occurred
on a non-standard port, in the window — after excluding CDN/telemetry/DNS-based
security services that legitimately use long labels.

## 3. Scope

- **Time window:** last 1–3 days (tight window keeps volume/entropy math sharp)
- **Environment scope:** all endpoints with DNS and/or network telemetry
- **Known-good baseline:** CDNs, anti-malware/DNS-security lookups, and some SaaS
  encode long tokens into subdomains. Baseline those parent domains and exclude
  them before alerting.

## 4. Hunt Query

```kql
// T1048.003: DNS tunneling — high query volume + long, high-entropy subdomains.
let lookback = 1d;
let min_queries = 100;            // many queries to one parent domain
let min_avg_sublen = 25;         // long encoded labels
let min_avg_entropy = 3.5;       // near-random character distribution
let excluded_parents = dynamic(["in-addr.arpa","ip6.arpa","akamaiedge.net",
    "cloudfront.net","microsoft.com","windowsupdate.com","office365.com",
    "trafficmanager.net","edgekey.net","opendns.com"]);
DnsEvents
| where TimeGenerated > ago(lookback)
| where isnotempty(Name)
| extend Fqdn = tolower(Name)
| extend Labels = split(Fqdn, ".")
| extend Parent = strcat(tostring(Labels[array_length(Labels)-2]), ".",
                         tostring(Labels[array_length(Labels)-1]))
| where Parent !in (excluded_parents)
| extend SubLen = strlen(Fqdn) - strlen(Parent)
// Shannon entropy over the sub-domain portion:
| extend Sub = substring(Fqdn, 0, SubLen)
| extend Chars = extract_all(@"(.)", Sub)
| mv-expand Ch = Chars to typeof(string)
| summarize CharCnt = count() by ClientIP, Computer, Parent, Fqdn, Sub, SubLen, Ch
| summarize Entropy = -sum((todouble(CharCnt)/strlen(any(Sub))) *
                           log2(todouble(CharCnt)/strlen(any(Sub)))),
            SubLen = any(SubLen)
    by ClientIP, Computer, Parent, Fqdn
| summarize Queries = dcount(Fqdn),
            AvgSubLen = avg(SubLen),
            AvgEntropy = avg(Entropy),
            SampleFqdns = make_set(Fqdn, 8)
    by ClientIP, Computer, Parent
| where Queries >= min_queries
    and AvgSubLen >= min_avg_sublen
    and AvgEntropy >= min_avg_entropy
| order by Queries desc, AvgEntropy desc
```

**Pivots / follow-up queries:**

```kql
// Defender-only variant: DNS-over-port-53 volume from a host to one destination,
// where DnsEvents is not available. Flags per-host DNS chattiness spikes.
let lookback = 1d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemotePort == 53 and ActionType == "ConnectionSuccess"
| summarize Queries = count(),
            SentBytes = sum(tolong(column_ifexists("SentBytes", long(0)))),
            Procs = make_set(InitiatingProcessFileName, 10)
    by DeviceName, RemoteIP, bin(Timestamp, 1h)
| where Queries >= 200
| order by Queries desc
```

```kql
// Non-standard-port bulk transfer (T1048): large outbound on an odd port.
let lookback = 1d;
let common_ports = dynamic([53,80,88,123,135,389,443,445,636,3389,5985,5986]);
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| where RemotePort !in (common_ports) and RemotePort > 1024
| summarize SentMB = round(sum(tolong(column_ifexists("SentBytes", long(0)))) / 1048576.0, 2),
            Conns = count(), Procs = make_set(InitiatingProcessFileName, 10)
    by DeviceName, RemoteIP, RemotePort
| where SentMB >= 10
| order by SentMB desc
```

## 5. Triage Guidance

- **Benign indicators:** the parent domain is a known CDN / DNS-security /
  telemetry service that legitimately uses long encoded labels; the odd-port
  transfer is a known application on a documented port.
- **Suspicious indicators:** hundreds+ of queries to one rare parent domain with
  long, high-entropy subdomains; DNS driven by a non-resolver process; a
  multi-MB transfer on an uncommon high port to a rare destination.
- **Malicious confirmation:** the parent domain resolves to attacker
  infrastructure / matches tunneling IOCs, decoding the subdomains yields staged
  data, or a known tunneler (`iodine`, `dnscat2`, `dnsexfiltrator`) is running.

## Validation (Purple Team)

Validate this hunt fires against a **safe, authorized lab** before relying on it.

- **Simulate:** stand up `dnscat2` or `iodine` (or `DNSExfiltrator`) in a lab and tunnel a file out over DNS; for the port variant, `Invoke-AtomicTest T1048` (bulk transfer over a non-standard port).
- **Expected hit:** the primary query surfaces the host↔lab-parent-domain pair with high `Queries`, `AvgSubLen`, and `AvgEntropy`; the port pivot surfaces the odd-port transfer with high `SentMB`.
- **If it does NOT fire:** check data-source ingestion, the time window, and any
  baseline exclusions that may be over-broad — then re-run and re-tune.

> Run adversary simulations only in an environment you are authorized to test.

## 6. Outcome

- [ ] Detection promoted (analytic rule)
- [ ] Incident raised
- [ ] Visibility gap filed (is DnsEvents ingested? do you have port-53 payload visibility?)
- [ ] Documented clear

**Notes:** Entropy math over `mv-expand` is expensive — narrow the time window
and pre-filter on `SubLen` before computing entropy in production. If `DnsEvents`
is unavailable, the port-53 volume pivot on `DeviceNetworkEvents` is your fallback
signal, at the cost of subdomain-content visibility.

---

## References

- https://attack.mitre.org/techniques/T1048/
- https://attack.mitre.org/techniques/T1048/003/