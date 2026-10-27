---
brief_id: brief-2026-10-27-rapidjson-oob-read
event_id: brief-2026-10-27-rapidjson-oob-read
revision: 1
activity_at: "2026-10-27T01:52:21Z"
title: 'RapidJSON: Out-of-bounds read in Regex Parser (CVE-2026-116620)'
slug: 2026-10-rapidjson-oob-read
description: Tencent RapidJSON versions up to 1.1.0 contain an out-of-bounds read vulnerability in the GenericStringStream function within the Regex Parser component.
date: "2026-10-27T01:52:21Z"
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
  - cpe:2.3:a:tencent:rapidjson:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rapidjson
vendors:
  - Tencent
products:
  - RapidJSON (<= 1.1.0)
cves:
  - id: CVE-2026-116620
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116620
---

A security vulnerability has been detected in Tencent RapidJSON up to 1.1.0. The issue affects the function `GenericStringStream<UTF8<char>>::Take` in the file `include/rapidjson/stream.h` of the component Regex Parser. The manipulation leads to an out-of-bounds read and can be initiated remotely. The exploit has been disclosed publicly. The project was informed of the problem but has not responded.
