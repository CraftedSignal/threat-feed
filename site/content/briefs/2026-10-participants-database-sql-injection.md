---
brief_id: brief-2026-10-23-participants-database-sql-injection
event_id: brief-2026-10-23-participants-database-sql-injection
revision: 1
activity_at: "2026-10-23T09:35:42Z"
title: 'Participants Database: Blind SQL Injection (CVE-2026-112860)'
slug: 2026-10-participants-database-sql-injection
description: Participants Database (xnau webdesign) versions from n/a through 2.7.8.5 are affected by a Blind SQL Injection vulnerability.
date: "2026-10-23T09:35:42Z"
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
cpes:
  - cpe:2.3:a:xnau_webdesign:participants_database:*:*:*:*:*:*:*:*
vendors:
  - xnau webdesign
products:
  - Participants Database (n/a - 2.7.8.5)
cves:
  - id: CVE-2026-112860
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112860
---

Participants Database (xnau webdesign) contains an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability. This issue allows for Blind SQL Injection and affects versions from n/a through 2.7.8.5.
