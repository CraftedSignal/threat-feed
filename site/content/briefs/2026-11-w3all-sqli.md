---
brief_id: brief-2026-11-09-w3all-sqli
event_id: brief-2026-11-09-w3all-sqli
revision: 1
activity_at: "2026-11-09T19:59:36Z"
title: 'WP w3all phpBB: SQL injection (CVE-2026-121769)'
slug: 2026-11-w3all-sqli
description: The axew3.com WP w3all phpBB plugin for WordPress contains an SQL injection vulnerability (CVE-2026-121769) caused by improper neutralization of special elements used in an SQL command. This issue affects versions up to 3.1.9.
date: "2026-11-09T19:59:36Z"
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
  - cpe:2.3:a:axew3:wp_w3all_phpbb_integration:*:*:*:*:*:wordpress:*:*
vendors:
  - axew3
products:
  - WP w3all phpBB (<= 3.1.9)
cves:
  - id: CVE-2026-121769
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121769
---

The WP w3all phpBB plugin (versions up to 3.1.9) is affected by an SQL Injection vulnerability identified as CVE-2026-121769. The vulnerability is characterized by the improper neutralization of special elements used in an SQL command.
