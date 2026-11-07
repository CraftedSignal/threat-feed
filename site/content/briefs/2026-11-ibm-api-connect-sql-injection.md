---
brief_id: brief-2026-11-07-ibm-api-connect-sql-injection
event_id: brief-2026-11-07-ibm-api-connect-sql-injection
revision: 1
activity_at: "2026-11-07T05:54:23Z"
title: 'IBM API Connect: Remote SQL Injection (CVE-2026-17336)'
slug: 2026-11-ibm-api-connect-sql-injection
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to remote SQL injection, allowing authenticated attackers to execute arbitrary SQL commands.
date: "2026-11-07T05:54:23Z"
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
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-17336
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17336
---

IBM API Connect 12.1.0.0 through 12.1.1.2 contains a vulnerability where improper neutralization of special elements used in an SQL command could allow a remote authenticated attacker to execute arbitrary SQL commands. This vulnerability carries a CVSS v3.1 base score of 9.9.
