---
brief_id: brief-2026-10-26-open5gs-heap-oob-write
event_id: brief-2026-10-26-open5gs-heap-oob-write
revision: 1
activity_at: "2026-10-26T17:44:50Z"
title: 'Open5GS: Heap out-of-bounds write in parse_multipart (CVE-2026-116543)'
slug: 2026-10-open5gs-heap-oob-write
description: Open5GS versions 1.3.0 through 2.8.0 contain a heap out-of-bounds write vulnerability in the parse_multipart() function, allowing unauthenticated attackers to corrupt memory and crash network functions.
date: "2026-10-26T17:44:50Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Open5GS (1.3.0 through 2.8.0)
cves:
  - id: CVE-2026-116543
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116543
---

A heap out-of-bounds write vulnerability exists in the parse_multipart() function of Open5GS versions 1.3.0 through 2.8.0. Unauthenticated attackers can exploit this by sending a crafted multipart/related request to the SBI interface of any network function. This triggers an overflow of the lookbehind buffer, resulting in memory corruption and a crash of the affected network function.
