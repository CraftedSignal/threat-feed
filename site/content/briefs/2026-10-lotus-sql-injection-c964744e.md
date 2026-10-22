---
brief_id: brief-2026-10-22-lotus-sql-injection-c964744e
event_id: brief-2026-10-22-lotus-sql-injection-c964744e
revision: 1
activity_at: "2026-10-22T16:14:24Z"
title: 'Lotus: SQL injection in billable metrics (CVE-2026-115331)'
slug: 2026-10-lotus-sql-injection-c964744e
description: Lotus versions through 0.10.2 contain an SQL injection vulnerability that allows authenticated organization users to inject SQL via billable metric property_name or categorical filter values.
date: "2026-10-22T16:14:24Z"
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
  - cpe:2.3:a:lotus:lotus:*:*:*:*:*:*:*:*
vendors:
  - Lotus
products:
  - Lotus (<= 0.10.2)
cves:
  - id: CVE-2026-115331
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115331
---

Lotus versions through 0.10.2 contain an SQL injection vulnerability. Authenticated organization users can inject SQL by supplying crafted billable metric property_name or categorical filter values. These values are rendered unescaped into Jinja-generated counter, gauge, and rate metric queries, allowing access to the database shared by all tenants.
