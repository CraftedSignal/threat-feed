---
brief_id: brief-2026-10-26-crocoblock-jetengine-sql-injection
event_id: brief-2026-10-26-crocoblock-jetengine-sql-injection
revision: 1
activity_at: "2026-10-26T11:41:55Z"
title: 'Crocoblock JetEngine: SQL injection (CVE-2026-115608)'
slug: 2026-10-crocoblock-jetengine-sql-injection
description: The Crocoblock JetEngine plugin is affected by an Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) vulnerability in versions up to 3.9.0.
date: "2026-10-26T11:41:55Z"
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
  - cpe:2.3:a:crocoblock:jetengine:*:*:*:*:*:*:*:*
vendors:
  - Crocoblock
products:
  - JetEngine (n/a through 3.9.0)
cves:
  - id: CVE-2026-115608
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115608
---

Crocoblock JetEngine plugin is affected by an SQL Injection vulnerability, identified as CVE-2026-115608. This issue arises from improper neutralization of special elements used in an SQL command and affects versions up to 3.9.0.
