---
brief_id: brief-2026-11-06-whale-browser-sandbox-bypass
event_id: brief-2026-11-06-whale-browser-sandbox-bypass
revision: 1
activity_at: "2026-11-06T21:29:19Z"
title: 'Whale Browser: Iframe sandbox bypass (CVE-2026-120987)'
slug: 2026-11-whale-browser-sandbox-bypass
description: Whale Browser before 5.39.412.57 allows an attacker to bypass the iframe sandbox in a dual-tab environment.
date: "2026-11-06T21:29:19Z"
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
products:
  - Whale Browser (< 5.39.412.57)
cves:
  - id: CVE-2026-120987
    cvss: 7.5
    epss: 0.00113
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120987
---

Whale Browser before 5.39.412.57 contains a vulnerability that allows an attacker to bypass the iframe sandbox in a dual-tab environment.
