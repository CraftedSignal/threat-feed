---
brief_id: brief-2026-10-21-videowhisper-xss
event_id: brief-2026-10-21-videowhisper-xss
revision: 1
activity_at: "2026-10-21T16:08:49Z"
title: VideoWhisper Paid Videochat Turnkey Site Reflected Cross-Site Scripting (CVE-2026-111840)
slug: 2026-10-videowhisper-xss
description: VideoWhisper Paid Videochat Turnkey Site (from n/a through 7.5.14) is vulnerable to Reflected Cross-site Scripting (XSS) due to improper neutralization of input during web page generation.
date: "2026-10-21T16:08:49Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cpes:
  - cpe:2.3:a:videowhisper:paid_videochat_turnkey_site:*:*:*:*:*:*:*:*
vendors:
  - VideoWhisper
products:
  - Paid Videochat Turnkey Site (n/a - 7.5.14)
cves:
  - id: CVE-2026-111840
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111840
---

VideoWhisper Paid Videochat Turnkey Site, versions from n/a through 7.5.14, contains a vulnerability identified as Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'). This allows for Reflected XSS.

## Technical Details
- Vulnerability Type: Cross-site Scripting (CWE-79)
- CVSS v3.1 Base Score: 7.1
