---
brief_id: brief-2026-11-03-dameware-rce
event_id: brief-2026-11-03-dameware-rce
revision: 1
activity_at: "2026-11-03T18:01:47Z"
title: SolarWinds Dameware buffer overflow remote code execution (CVE-2026-28335)
slug: 2026-11-dameware-rce
description: SolarWinds Dameware is affected by a buffer overflow vulnerability that can result in remote code execution. Authentication is required.
date: "2026-11-03T18:01:47Z"
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
  - cpe:2.3:a:solarwinds:dameware:*:*:*:*:*:*:*:*
vendors:
  - SolarWinds
products:
  - Dameware
cves:
  - id: CVE-2026-28335
    cvss: 8.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28335
---

SolarWinds Dameware has been identified as affected by a buffer overflow vulnerability (CVE-2026-28335) that can result in remote code execution. Authentication is required to exploit this vulnerability.
