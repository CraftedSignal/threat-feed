---
title: Active Exploitation of Citrix NetScaler Vulnerabilities CVE-2026-88771 and CVE-2026-88772
slug: 2026-09-citrix-kev
description: CISA has added two Citrix NetScaler vulnerabilities to its Known Exploited Vulnerabilities catalog due to documented evidence of active in-the-wild exploitation.
date: "2026-09-27T19:54:07Z"
lastmod: "2026-09-28T07:47:22Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=47F4D662-7265-5507-AF7B-22B94A1EC716&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - exploitation
  - network-appliance
vendors:
  - Citrix
products:
  - NetScaler ADC (< 14.1-73.37)
  - NetScaler Gateway (< 14.1-73.37)
cves:
  - id: CVE-2026-88771
  - id: CVE-2026-88772
references:
  - https://sploitus.com/exploit?id=47F4D662-7265-5507-AF7B-22B94A1EC716&utm_source=rss&utm_medium=rss
  - https://www.cve.org/CVERecord?id=CVE-2026-88772
  - https://www.securityweek.com/citrix-confirms-2-netscaler-zero-days-after-admins-pulled-the-plug/
updates:
  - at: "2026-09-27T21:59:19Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=47F4D662-7265-5507-AF7B-22B94A1EC716&utm_source=rss&utm_medium=rss
  - at: "2026-09-28T01:21:41Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-88772
  - at: "2026-09-28T07:47:22Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/citrix-confirms-2-netscaler-zero-days-after-admins-pulled-the-plug/
---

CISA has officially added two vulnerabilities affecting Citrix NetScaler to its Known Exploited Vulnerabilities (KEV) Catalog, citing evidence of active exploitation in the wild. The identified vulnerabilities are CVE-2026-88771, which involves improper input validation, and CVE-2026-88772, which involves improper restriction of operations within the bounds of a memory buffer. These vulnerabilities are documented as frequent attack vectors that allow malicious actors to target organizations by exploiting weaknesses in input handling and memory management on network appliances. Given their inclusion in the KEV catalog, these flaws are considered high-risk, necessitating immediate remediation to prevent potential unauthorized access or system compromise. Defenders should prioritize patching all internet-facing NetScaler instances to mitigate the risk posed by these actively exploited CVEs.

## Impact

Successful exploitation of these vulnerabilities in Citrix NetScaler appliances can grant attackers unauthorized control over affected assets. Because NetScaler devices often sit at the network edge as gateways or load balancers, compromise poses a significant risk to the integrity and confidentiality of the entire internal enterprise environment. Organizations that fail to patch these vulnerabilities risk total asset takeover by threat actors.

## Recommendation

- Immediately identify all internet-facing Citrix NetScaler instances and apply the latest security patches provided by the vendor to address CVE-2026-88771 and CVE-2026-88772.
- Implement a risk-based vulnerability management program as recommended by CISA, prioritizing KEV catalog entries for immediate remediation.
- Audit network logs and administrative access logs for unusual activity originating from or targeting NetScaler management interfaces, as exploitation often involves unauthorized input or memory manipulation.
- Review CISA Binding Operational Directive 26-04 for guidance on required forensic checks for signs of compromise on assets where these vulnerabilities were present prior to patching.
