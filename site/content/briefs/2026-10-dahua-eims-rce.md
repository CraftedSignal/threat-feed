---
brief_id: brief-2026-10-26-dahua-eims-rce
event_id: brief-2026-10-26-dahua-eims-rce
revision: 1
activity_at: "2026-10-26T18:01:51Z"
title: 'Dahua Eims: Unauthenticated Remote OS Command Injection (CVE-2024-13985)'
slug: 2026-10-dahua-eims-rce
description: A public proof-of-concept exploit has been published for CVE-2024-13985, an unauthenticated remote OS command injection vulnerability in Dahua Eims.
date: "2026-10-26T18:01:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:dahua:eims:*:*:*:*:*:*:*:*
vendors:
  - Dahua
products:
  - Eims
cves:
  - id: CVE-2024-13985
    epss: 0.15095
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=44F330E2-7DF1-5D49-AA0A-305C3B0902E3
  - https://sploitus.com/exploit?id=44F330E2-7DF1-5D49-AA0A-305C3B0902E3&utm_source=rss&utm_medium=rss
---

CVE-2024-13985 is a vulnerability affecting Dahua Eims. The vulnerability allows for unauthenticated remote OS command injection via the 'captureCommand' parameter to the 'capture_handle.action' endpoint, enabling arbitrary commands on the server. Public proof-of-concept exploit code has been published on Sploitus.
