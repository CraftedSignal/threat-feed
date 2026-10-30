---
brief_id: brief-2026-10-30-mirth-connect-rce
event_id: brief-2026-10-30-mirth-connect-rce
revision: 1
activity_at: "2026-10-30T02:28:39Z"
title: 'Nextgen Mirth Connect: Remote code execution via XStream deserialization (CVE-2023-43208)'
slug: 2026-10-mirth-connect-rce
description: A public proof-of-concept exploit is available for a remote code execution vulnerability in Mirth Connect (versions prior to 4.4.1) involving XStream deserialization via the API.
date: "2026-10-30T02:28:39Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:nextgen:mirth_connect:*:*:*:*:*:*:*:*
products:
  - Mirth Connect (< 4.4.1)
cves:
  - id: CVE-2023-43208
    cvss: 9.8
    epss: 0.85423
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HUMBERTO-PIXEL-CVE-2023-43208-POC
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HUMBERTO-PIXEL-CVE-2023-43208-POC&utm_source=rss&utm_medium=rss
---
