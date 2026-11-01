---
brief_id: brief-2026-11-01-bookit-sql-injection
event_id: brief-2026-11-01-bookit-sql-injection
revision: 1
activity_at: "2026-11-01T18:57:16Z"
title: 'BookIt: SQL injection vulnerability (CVE-2026-62048)'
slug: 2026-11-bookit-sql-injection
description: Liquid Web / StellarWP BookIt contains an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability.
date: "2026-11-01T18:57:16Z"
type: advisory
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
vendors:
  - Liquid Web
  - StellarWP
products:
  - BookIt (n/a through 2.6.0.6)
cves:
  - id: CVE-2026-62048
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62048
---

The BookIt plugin (by Liquid Web / StellarWP) contains an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability. This issue affects BookIt from versions n/a through 2.6.0.6. The CVSS v3.1 base score for this vulnerability is 9.3.
