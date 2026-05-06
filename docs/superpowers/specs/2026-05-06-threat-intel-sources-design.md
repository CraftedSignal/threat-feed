# Threat Intel Source Catalog — Design Spec

**Date:** 2026-05-06  
**Status:** Approved  
**Scope:** Define the complete set of external sources ti-bot should monitor for threat actor campaign reports, APT research, and malware analysis — complementing the existing CVE/vulnerability coverage.

---

## Problem

The feed ingests CVE/advisory content well (NVD, GitHub Advisories, VulDB, VulnCheck) but threat actor campaign reports from major vendors are nearly absent: Securelist appears in 2 briefs, Mandiant in 1, Unit42 in 2, across 2000+ total briefs. Articles like the Kaspersky Securelist DAEMON Tools supply chain backdoor (May 2026) are missed entirely because no systematic source coverage exists for threat campaign reporting.

---

## Design

### Deduplication Model

**Enrichment with actor aliases (Option C):**

1. First Tier 1 source to report a campaign creates a new brief.
2. Subsequent reports from any source that match an existing brief within a **30-day window** trigger an update (additional references, IOCs, TTPs merged) rather than a new brief.
3. Campaign matching fingerprint: `(actor OR CVE) + (target sector OR malware family)`.
4. Actor aliases in `site/data/actor_aliases.yaml` are applied before matching — vendor-specific names (e.g., CrowdStrike "Bear", Mandiant "Cozy Bear") resolve to the canonical group before deduplication.

### Source Tiers

| Tier | Behaviour |
|---|---|
| **Tier 1** | Novel campaign report → creates new brief. First-reporter wins. |
| **Tier 2** | Same campaign matched → enriches existing brief. Creates new brief only if no match found within window. |

### Categories

Four categories: Commercial Vendors, Government/CERT, ISACs, Independent Research.

---

## Source Catalog

### Commercial Vendors — Tier 1

| Vendor | RSS Feed | Notes |
|---|---|---|
| Mandiant / Google TI | `https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/` | Mandiant research team post-Google acquisition |
| CrowdStrike | `https://www.crowdstrike.com/blog/feed/` | Filter to adversary intel / eCrime categories |
| Palo Alto Unit 42 | `https://unit42.paloaltonetworks.com/feed/` | Dedicated research division, high output |
| Kaspersky Securelist | `https://securelist.com/feed/` | GReAT team; highest signal for APT research globally |
| SentinelOne SentinelLabs | `https://www.sentinelone.com/labs/feed/` | Use `/labs/` not `/blog/` |
| Microsoft Security (MSTIC) | `https://www.microsoft.com/en-us/security/blog/feed/` | Source of Blizzard/Typhoon actor naming |
| Cisco Talos | `https://feeds.feedburner.com/feedburner/Talos` | Direct blog path returns 403; FeedBurner URL works |
| Volexity | `https://www.volexity.com/feed/` | Frequently first to disclose APT zero-day exploitation |
| The DFIR Report | `https://thedfirreport.com/feed/` | Full intrusion timelines with IOCs and TTPs per post |

### Commercial Vendors — Tier 2

| Vendor | RSS Feed | Notes |
|---|---|---|
| ESET WeLiveSecurity | `https://feeds.feedburner.com/eset/blog` | Strong on Eastern European/Russian actors |
| Elastic Security Labs | `https://www.elastic.co/security-labs/rss/feed.xml` | Detection-focused; behavioral analysis |
| Check Point Research | `https://research.checkpoint.com/feed/` | Consistent original research output |
| Sophos X-Ops | `https://www.sophos.com/en-us/category/threat-research/feed` | Includes former Secureworks CTU (acquired Feb 2025) |
| Bitdefender Labs | `https://www.bitdefender.com/blog/api/rss/labs/` | Custom endpoint — not `/feed/` |
| Fortinet FortiGuard | `https://feeds.fortinet.com/fortinet/blog/threat-research` | ICS/OT + ransomware tracking |
| Proofpoint Threat Insight | `https://www.proofpoint.com/us/threat-insight-blog.xml` | Email threats, initial access brokers, TA-designated actors |
| Huntress | `https://www.huntress.com/blog/rss.xml` | Rapid-response on active campaigns targeting MSPs/SMBs |
| Rapid7 Emergent Threat | `https://www.rapid7.com/blog/tag/emergent-threat-response/rss/` | Actively exploited CVEs with exploitation context |
| Red Canary | `https://redcanary.com/blog/feed/` | ATT&CK mapping, detection research |
| Recorded Future | `https://www.recordedfuture.com/feed` | Filter to Research/Threat Intelligence categories |
| Flashpoint | `https://flashpoint.io/blog/feed/` | Criminal forums, dark web, access brokers |
| Intel 471 | `https://www.intel471.com/blog/feed` | Criminal underground, ransomware group tracking |
| GreyNoise | `https://www.greynoise.io/blog/rss.xml` | Mass exploitation tracking, internet-wide scanning |
| Cofense | `https://cofense.com/feed/` | Email-borne threats, phishing campaigns |
| Google Project Zero | `https://projectzero.google/feed.xml` | Zero-day root cause analysis |
| ANY.RUN | `https://any.run/cybersecurity-blog/feed/` | Active malware campaigns, sandbox findings |
| Qualys Threat Research | `https://blog.qualys.com/vulnerabilities-threat-research/feed` | Patch Tuesday analysis, exploitation context |
| Malware Traffic Analysis | `https://malware-traffic-analysis.net/blog-entries.rss` | PCAPs + samples from active distribution campaigns |
| Objective-See | `https://objective-see.org/rss.xml` | macOS-specific malware and APT campaigns (Patrick Wardle) |
| AttackIQ | `https://attackiq.com/blog/feed/` | Threat actor emulation, ATT&CK coverage analysis |

### Commercial Vendors — No Working RSS

| Vendor | Issue | Alternative |
|---|---|---|
| IBM X-Force | RSS defunct post `securityintelligence.com` → `ibm.com/think` migration | Monitor blog directly |
| Lumen Black Lotus Labs | No RSS exposed | Monitor `blog.lumen.com` directly |
| Trend Micro Research | Blocks RSS crawlers (403) | Scraping required |
| Trellix ARC | No public RSS | Monitor directly |
| Group-IB | Feed returns 403 | Monitor directly |
| Zscaler ThreatLabz | No RSS; email subscription only | Email subscription |
| Symantec/Broadcom | Feed dead post-Broadcom acquisition | Absorbed into Sophos — use Sophos feed above |

### Government / CERT — Tier 1

All government/CERT sources are Tier 1 for novel attribution or active exploitation advisories; Tier 2 for corroborating advisories that reference already-briefed campaigns.

| Source | Country | RSS Feed | Notes |
|---|---|---|---|
| NCSC-UK | UK | `https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml` | Joint advisories, APT attribution, malware reports |
| FBI Cyber (IC3) | US | `https://www.ic3.gov/PSA/RSS` | PSAs on ransomware, nation-state intrusions, BEC |
| CERT-EU | EU | `https://cert.europa.eu/publications/threat-intelligence-rss` | Monthly Cyber Briefs, threat landscape reports |
| CCCS | Canada | `https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en` | Security advisories, threat alerts |
| JPCERT/CC | Japan | `https://www.jpcert.or.jp/english/rss/jpcert-en.rdf` | English subset; strong on APAC-region threats |
| ASD/ACSC | Australia | `https://www.cyber.gov.au/rss/alerts` | Officially documented URL; may be geo-restricted |
| ASD/ACSC advisories | Australia | `https://www.cyber.gov.au/rss/advisories` | Officially documented URL |
| MS-ISAC (via CIS) | US SLTT | `https://www.cisecurity.org/advisory/feed` | Vulnerability advisories for state/local government |

### Government / CERT — No RSS or RSS Discontinued

| Source | Issue | Alternative |
|---|---|---|
| CISA | RSS **discontinued May 2025** | KEV JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; advisories via `github.com/cisagov/CSAF` |
| NSA Cybersecurity | No public RSS | GovDelivery + monitor `nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/` |
| NCSC-NZ | Email only | Monitor `ncsc.govt.nz/alerts/` directly |
| CSA Singapore | No RSS | Monitor `csa.gov.sg/News/Publications` directly |
| ANSSI (France) | French RSS only | English reports published ad hoc — monitor manually |
| BSI (Germany) | German RSS only | English annual report only — monitor manually |
| NCSC-NL (Netherlands) | Dutch RSS only | No English feed |

### ISACs

FS-ISAC and H-ISAC are member-gated with no public RSS — excluded.  
MS-ISAC is listed under Government/CERT above.

### Independent Research — Tier 2

| Source | RSS Feed | Notes |
|---|---|---|
| Google TAG | `https://blog.google/threat-analysis-group/rss/` | Government-backed attackers, 0-day in-the-wild, spyware vendors |

---

## CISA Replacement Ingestion

CISA RSS was discontinued May 12, 2025. The feed currently has 44 CISA references — if ti-bot's CISA ingestion is RSS-based, it has been broken since May 2025. Two replacement paths:

1. **KEV JSON polling** — `cisa.gov/.../known_exploited_vulnerabilities.json` — new KEV entries enrich existing CVE briefs or trigger new advisory briefs.
2. **CSAF GitHub repo watching** — `github.com/cisagov/CSAF` — advisories committed as structured JSON; ti-bot watches for new commits.

---

## Summary

| Category | Tier 1 feeds | Tier 2 feeds | No RSS |
|---|---|---|---|
| Commercial vendors | 9 | 21 | 7 |
| Government/CERT | 7 | — | 4 + 3 non-English |
| Independent | — | 1 | — |
| **Total** | **16** | **22** | **14** |

38 feeds with working RSS to add. 14 sources without RSS require direct monitoring or alternative ingestion mechanisms.
