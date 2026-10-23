---
brief_id: brief-2026-10-23-gamipress-sql-injection
event_id: brief-2026-10-23-gamipress-sql-injection
revision: 1
activity_at: "2026-10-23T09:35:29Z"
title: 'GamiPress: Blind SQL Injection (CVE-2026-112837)'
slug: 2026-10-gamipress-sql-injection
description: GamiPress versions n/a through 8.0.7 contain an Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) vulnerability, specifically allowing Blind SQL Injection.
date: "2026-10-23T09:35:29Z"
type: advisory
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
  - cpe:2.3:a:ruben_garcia:gamipress:*:*:*:*:*:*:*:*
vendors:
  - Ruben Garcia
products:
  - GamiPress (n/a through 8.0.7)
cves:
  - id: CVE-2026-112837
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112837
---

CVE-2026-112837 is a Blind SQL Injection vulnerability in the Ruben Garcia GamiPress plugin. The vulnerability is caused by improper neutralization of special elements used in an SQL command. The issue affects GamiPress from n/a through 8.0.7.
