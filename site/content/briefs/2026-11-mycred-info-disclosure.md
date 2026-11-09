---
brief_id: brief-2026-11-09-mycred-info-disclosure
event_id: brief-2026-11-09-mycred-info-disclosure
revision: 1
activity_at: "2026-11-09T13:48:56Z"
title: 'myCred: Exposure of Sensitive System Information (CVE-2026-123465)'
slug: 2026-11-mycred-info-disclosure
description: An Exposure of Sensitive System Information to an Unauthorized Control Sphere vulnerability in myCred allows for the retrieval of embedded sensitive data.
date: "2026-11-09T13:48:56Z"
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
  - cpe:2.3:a:mycred:mycred:*:*:*:*:*:*:*:*
vendors:
  - myCred
products:
  - myCred (n/a through 4.0.2)
cves:
  - id: CVE-2026-123465
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123465
---

The myCred application contains an Exposure of Sensitive System Information to an Unauthorized Control Sphere vulnerability (CVE-2026-123465). This issue allows for the retrieval of embedded sensitive data. The vulnerability affects myCred versions from n/a through 4.0.2.
