---
brief_id: brief-2026-10-26-nexopos-directory-traversal
event_id: brief-2026-10-26-nexopos-directory-traversal
revision: 1
activity_at: "2026-10-26T15:44:24Z"
title: 'NexoPOS: Directory Traversal via api/update (CVE-2026-107092)'
slug: 2026-10-nexopos-directory-traversal
description: NexoPOS version 6.2.4 is vulnerable to Directory Traversal via the api/update endpoint.
date: "2026-10-26T15:44:24Z"
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
  - cpe:2.3:a:nexopos:nexopos:6.2.4:*:*:*:*:*:*:*
vendors:
  - NexoPOS
products:
  - NexoPOS (6.2.4)
cves:
  - id: CVE-2026-107092
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107092
---

NexoPOS version 6.2.4 contains a directory traversal vulnerability in the api/update endpoint, as identified by CVE-2026-107092. The CVSS v3.1 base score for this vulnerability is 9.8.
