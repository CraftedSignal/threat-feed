---
brief_id: brief-2026-11-05-fflate-memory-corruption
event_id: brief-2026-11-05-fflate-memory-corruption
revision: 1
activity_at: "2026-11-05T04:27:17Z"
title: 'fflate: Memory corruption in unzipSync (CVE-2026-122146)'
slug: 2026-11-fflate-memory-corruption
description: A memory corruption vulnerability has been identified in 101arrowz fflate up to version 0.8.3 within the unzipSync function.
date: "2026-11-05T04:27:17Z"
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
  - cpe:2.3:a:101arrowz:fflate:*:*:*:*:*:*:*:*
vendors:
  - 101arrowz
products:
  - fflate (<= 0.8.3)
cves:
  - id: CVE-2026-122146
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122146
---

A weakness exists in 101arrowz fflate up to version 0.8.3. The issue affects the `unzipSync` function in `esm/index.mjs` and causes memory corruption. The attack can be initiated remotely, and public exploit code is available. The vendor did not respond to initial disclosure attempts.
