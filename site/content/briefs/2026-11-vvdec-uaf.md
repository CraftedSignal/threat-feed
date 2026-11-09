---
brief_id: brief-2026-11-09-vvdec-uaf
event_id: brief-2026-11-09-vvdec-uaf
revision: 1
activity_at: "2026-11-09T23:17:40Z"
title: 'VVdeC: Heap use-after-free in AdaptiveLoopFilter (CVE-2026-124307)'
slug: 2026-11-vvdec-uaf
description: A heap use-after-free vulnerability in the VVdeC decoder (vvdecapp) occurs in AdaptiveLoopFilter::reconstructCoeff due to ALF APS redefinition.
date: "2026-11-09T23:17:40Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
tags:
  - vulnerability
  - memory-corruption
products:
  - VVdeC (vvdecapp) versions before 3.2.1
cves:
  - id: CVE-2026-124307
    cvss: 5.8
    epss: 0.0011
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/601
---

A heap use-after-free vulnerability (CWE-416) has been identified in VVdeC (vvdecapp) within the `AdaptiveLoopFilter::reconstructCoeff` function, triggered by a crafted VVC bitstream that performs an ALF (Adaptive Loop Filter) APS (Adaptation Parameter Set) redefinition. 

Affected versions include versions before 3.2.1. The issue was fixed in commit 1eddb30c4b8e02f3d13ba24aa7e52f1aa7b08c01.
