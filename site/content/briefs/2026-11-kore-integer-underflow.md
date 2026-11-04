---
brief_id: brief-2026-11-04-kore-integer-underflow
event_id: brief-2026-11-04-kore-integer-underflow
revision: 1
activity_at: "2026-11-04T02:27:09Z"
title: 'Kore: Integer underflow in HTTP request body handling (CVE-2026-121727)'
slug: 2026-11-kore-integer-underflow
description: Kore before 4.3.0 contains an integer underflow vulnerability in HTTP request body handling that allows unauthenticated attackers to bypass http_body_max and exhaust worker memory.
date: "2026-11-04T02:27:09Z"
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
  - Kore (< 4.3.0)
cves:
  - id: CVE-2026-121727
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121727
---

Kore before 4.3.0 contains an integer underflow vulnerability in HTTP request body handling that allows unauthenticated attackers to bypass http_body_max by sending more body bytes than declared. Attackers can send oversized first segments over many concurrent POST, PUT or DELETE connections, wrapping content_length to grow buffers unbounded and exhaust worker memory.
