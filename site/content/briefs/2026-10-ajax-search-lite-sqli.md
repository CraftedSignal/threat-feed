---
brief_id: brief-2026-10-21-ajax-search-lite-sqli
event_id: brief-2026-10-21-ajax-search-lite-sqli
revision: 1
activity_at: "2026-10-21T16:09:05Z"
title: 'WPdreams Ajax Search Lite: Blind SQL Injection (CVE-2026-111852)'
slug: 2026-10-ajax-search-lite-sqli
description: WPdreams Ajax Search Lite (up to version 4.14.6) contains a Blind SQL Injection vulnerability due to improper neutralization of special elements used in an SQL command.
date: "2026-10-21T16:09:05Z"
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
  - cpe:2.3:a:wpdreams:ajax_search_lite:*:*:*:*:*:*:*:*
vendors:
  - WPdreams
products:
  - Ajax Search Lite (n/a through 4.14.6)
cves:
  - id: CVE-2026-111852
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111852
---

CVE-2026-111852 identifies a Blind SQL Injection vulnerability in the WPdreams Ajax Search Lite plugin, affecting versions from n/a through 4.14.6. The vulnerability stems from improper neutralization of special elements used in an SQL command. The CVSS v3.1 base score is 9.3.
