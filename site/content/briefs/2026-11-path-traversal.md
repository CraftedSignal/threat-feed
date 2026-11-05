---
brief_id: brief-2026-11-05-path-traversal
event_id: brief-2026-11-05-path-traversal
revision: 1
activity_at: "2026-11-05T00:05:40Z"
title: 'Comfast CF-WR632AX: Multipart Parser path traversal (CVE-2026-122013)'
slug: 2026-11-path-traversal
description: A path traversal vulnerability exists in the Multipart Parser component of the Comfast CF-WR632AX (2.6.0.1) router.
date: "2026-11-05T00:05:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:h:comfast:cf-wr632ax:2.6.0.1:*:*:*:*:*:*:*
vendors:
  - Comfast
products:
  - CF-WR632AX (2.6.0.1)
cves:
  - id: CVE-2026-122013
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122013
---

A vulnerability has been identified in the Comfast CF-WR632AX firmware version 2.6.0.1. The issue resides in the /usr/bin/webmgnt component's Multipart Parser. By manipulating the 'filename' argument, an attacker can perform path traversal. The attack can be initiated remotely. The exploit is public, and the vendor has not responded to disclosure efforts.
