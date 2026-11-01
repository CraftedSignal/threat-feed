---
brief_id: brief-2026-11-01-wavlink-rce-df64a306
event_id: brief-2026-11-01-wavlink-rce-df64a306
revision: 1
activity_at: "2026-11-01T16:57:01Z"
title: 'WAVLINK WN553X1-B: OS command injection (CVE-2026-120231)'
slug: 2026-11-wavlink-rce-df64a306
description: A vulnerability in the OpenVPN CLI Handler component of the WAVLINK WN553X1-B (firmware V260403_2.0.0) allows remote OS command injection via the 'file_id' argument.
date: "2026-11-01T16:57:01Z"
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
products:
  - WN553X1-B (V260403_2.0.0)
cves:
  - id: CVE-2026-120231
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120231
---

A vulnerability (CVE-2026-120231) has been identified in WAVLINK WN553X1-B firmware version V260403_2.0.0. The flaw is located in the function 'sub_416568' of the file '/bin/ioos' within the OpenVPN CLI Handler component. Manipulation of the 'file_id' argument results in OS command injection. The attack can be initiated remotely. Publicly disclosed exploit code exists and may be utilized. The vendor was contacted early regarding this disclosure.
