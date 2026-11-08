---
brief_id: brief-2026-11-08-ibm-webmethods-auth-bypass
event_id: brief-2026-11-08-ibm-webmethods-auth-bypass
revision: 2
activity_at: "2026-11-08T20:57:30Z"
revision_history:
  - revision: 2
    at: "2026-11-08T20:57:30Z"
    checksum: sha256:aaae7ffb2b70ccca0e8c72f0670b107f2ae8292eddf928bdcaeccc29ddc1a2ad
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-117545&utm_source=rss&utm_medium=rss
title: 'IBM webMethods Integration Server: Authentication bypass (CVE-2026-117545)'
slug: 2026-11-ibm-webmethods-auth-bypass
description: IBM webMethods Integration Server 12.1 contains an improper authentication vulnerability that permits a remote authenticated attacker to bypass security restrictions.
date: "2026-11-08T19:35:15Z"
lastmod: "2026-11-08T20:56:55Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:ibm:webmethods_integration_server:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-117545&utm_source=rss&utm_medium=rss
vendors:
  - IBM
products:
  - webMethods Integration Server (12.1)
cves:
  - id: CVE-2026-117545
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117545
  - https://sploitus.com/exploit?id=CVE-2026-117545&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-08T20:56:55Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-117545&utm_source=rss&utm_medium=rss
---

IBM webMethods Integration Server 12.1 is vulnerable to an improper authentication flaw (CVE-2026-117545). This vulnerability could allow a remote authenticated attacker to bypass security restrictions. The issue has been assigned a CVSS v3.1 Base Score of 8.8.
