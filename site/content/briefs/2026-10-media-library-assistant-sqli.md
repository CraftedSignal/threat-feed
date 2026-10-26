---
brief_id: brief-2026-10-26-media-library-assistant-sqli
event_id: brief-2026-10-26-media-library-assistant-sqli
revision: 1
activity_at: "2026-10-26T13:42:14Z"
title: 'David Lingren Media Library Assistant: Blind SQL Injection (CVE-2026-115948)'
slug: 2026-10-media-library-assistant-sqli
description: David Lingren Media Library Assistant contains a Blind SQL Injection vulnerability due to improper neutralization of special elements used in an SQL command.
date: "2026-10-26T13:42:14Z"
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
  - cpe:2.3:a:david_lingren:media_library_assistant:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - vulnerability
vendors:
  - David Lingren
products:
  - Media Library Assistant (n/a through 3.42)
cves:
  - id: CVE-2026-115948
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115948
---

David Lingren Media Library Assistant is affected by a Blind SQL Injection vulnerability (CVE-2026-115948). The vulnerability involves the improper neutralization of special elements used in an SQL command. The affected versions range from n/a through 3.42.
