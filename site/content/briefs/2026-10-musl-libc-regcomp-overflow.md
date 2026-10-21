---
brief_id: brief-2026-10-21-musl-libc-regcomp-overflow
event_id: brief-2026-10-21-musl-libc-regcomp-overflow
revision: 1
activity_at: "2026-10-21T23:37:01Z"
title: 'musl libc: regcomp integer overflow (CVE-2026-107891)'
slug: 2026-10-musl-libc-regcomp-overflow
description: The regcomp function in musl libc is affected by multiple integer overflow issues which can lead to incorrectly-sized allocations and out-of-bounds heap writes.
date: "2026-10-21T23:37:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
products:
  - musl libc
cves:
  - id: CVE-2026-107891
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/289
---

The regcomp function in musl libc is affected by multiple integer overflow issues. These overflows are triggered by the size and complexity of the regular expression passed to regcomp, potentially leading to incorrect allocation sizes and out-of-bounds heap writes.
