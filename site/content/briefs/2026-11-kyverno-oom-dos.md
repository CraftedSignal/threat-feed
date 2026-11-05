---
brief_id: brief-2026-11-05-kyverno-oom-dos
event_id: brief-2026-11-05-kyverno-oom-dos
revision: 1
activity_at: "2026-11-05T04:27:57Z"
title: 'Kyverno: Unbounded decompression denial of service (CVE-2026-122322)'
slug: 2026-11-kyverno-oom-dos
description: Kyverno from 1.11.0 before 1.19.2 contains an unbounded decompression vulnerability in extractStatement that allows remote attackers to exhaust memory.
date: "2026-11-05T04:27:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Kyverno (1.11.0 to 1.19.1)
cves:
  - id: CVE-2026-122322
    cvss: 7.5
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122322
---

Kyverno versions 1.11.0 through 1.19.1 contain an unbounded decompression vulnerability in `extractStatement`. Attackers controlling registry referrer artifacts can push gzip predicate layers exceeding `maxPayloadSize` when decompressed, causing admission controller OOM kills and denial of service.
