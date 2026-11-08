---
brief_id: brief-2026-11-08-ibm-concert-rce
event_id: brief-2026-11-08-ibm-concert-rce
revision: 2
activity_at: "2026-11-08T20:57:30Z"
revision_history:
  - revision: 2
    at: "2026-11-08T20:57:30Z"
    checksum: sha256:68f494ca9f66f1360ae46f404b1dcb98189c500e625c112a2e83ba830a2cbd16
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-15266&utm_source=rss&utm_medium=rss
title: 'IBM Concert: Arbitrary command execution (CVE-2026-15266)'
slug: 2026-11-ibm-concert-rce
description: IBM Concert versions 1.0 through 3.0.1.1 contain components that allow potentially unsafe command execution, which could be exploited to run arbitrary system commands on the host.
date: "2026-11-08T19:33:11Z"
lastmod: "2026-11-08T20:56:55Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:ibm:concert:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-15266&utm_source=rss&utm_medium=rss
vendors:
  - IBM
products:
  - Concert (1.0 through 3.0.1.1)
cves:
  - id: CVE-2026-15266
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15266
  - https://sploitus.com/exploit?id=CVE-2026-15266&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-08T20:56:55Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-15266&utm_source=rss&utm_medium=rss
---

IBM Concert versions 1.0 through 3.0.1.1 contain components that allow potentially unsafe command execution. This vulnerability could be exploited to run arbitrary system commands on the host. The issue has been assigned a CVSS v3.1 base score of 9.8.
