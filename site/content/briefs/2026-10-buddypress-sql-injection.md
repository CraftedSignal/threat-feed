---
brief_id: brief-2026-10-29-buddypress-sql-injection
event_id: brief-2026-10-29-buddypress-sql-injection
revision: 1
activity_at: "2026-10-29T13:20:52Z"
title: 'BuddyPress: Blind SQL injection (CVE-2026-115965)'
slug: 2026-10-buddypress-sql-injection
description: BuddyPress versions from n/a through 14.5.2 contain a blind SQL injection vulnerability due to improper neutralization of special elements used in an SQL command.
date: "2026-10-29T13:20:52Z"
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
  - cpe:2.3:a:buddypress:buddypress:*:*:*:*:*:*:*:*
vendors:
  - BuddyPress
products:
  - BuddyPress (n/a through 14.5.2)
cves:
  - id: CVE-2026-115965
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115965
---

BuddyPress (versions n/a through 14.5.2) is affected by a Blind SQL Injection vulnerability (CVE-2026-115965). The issue is caused by the improper neutralization of special elements used in an SQL command.
