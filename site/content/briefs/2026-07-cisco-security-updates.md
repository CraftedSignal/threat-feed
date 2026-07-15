---
title: Cisco Security Updates — July 2026
slug: 2026-07-cisco-security-updates
description: Roundup of Cisco security advisories published in July 2026.
date: "2026-07-03T13:36:20Z"
lastmod: "2026-07-15T17:17:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Cisco
products:
  - Cisco devices
  - Cisco’s Smart Install (SMI) feature
  - Cisco Smart Install
  - Cisco Identity Services Engine
  - Cisco ISE Passive Identity Connector
  - Cisco RoomOS
cves:
  - id: CVE-2026-20146
    cvss: 5.5
  - id: CVE-2026-20150
    cvss: 8.8
references:
  - https://www.ncsc.gov.uk/news/uk-and-allies-urge-critical-sectors-to-improve-defences-against-russian-intelligence-targeting
  - https://www.darkreading.com/endpoint-security/weak-security-fuel-russian-cyberattacks
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-traversal-xNt7wb2Y?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Path%20Traversal%20Vulnerability%26vs_k=1
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20150
iocs:
  - type: url
    value: https://media.defense.gov/2026/Jul/09/2003959498/-1/-1/1/CSA_IMPROVE_ROUTER_HYGIENE.PDF
  - type: domain
    value: nvd.nist.gov
  - type: url
    value: https://nvd.nist.gov
  - type: email
    value: cve@mitre.org
  - type: email
    value: us-cert@us-cert.gov
ioc_counts:
  domain: 1
  email: 2
  url: 2
updates:
  - at: "2026-07-13T09:03:03Z"
    level: L1
    summary: new IOCs
    sources:
      - ncsc-uk
    source_urls:
      - https://www.ncsc.gov.uk/news/uk-and-allies-urge-critical-sectors-to-improve-defences-against-russian-intelligence-targeting
  - at: "2026-07-13T21:38:44Z"
    level: L1
    summary: new product
    sources:
      - dark-reading
    source_urls:
      - https://www.darkreading.com/endpoint-security/weak-security-fuel-russian-cyberattacks
  - at: "2026-07-15T16:03:34Z"
    level: L2
    summary: added CVE-2026-20146
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-traversal-xNt7wb2Y?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Path%20Traversal%20Vulnerability%26vs_k=1
  - at: "2026-07-15T17:17:39Z"
    level: L2
    summary: added CVE-2026-20150
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20150
---

Aggregated Cisco security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Cisco's July 2026 security updates.
