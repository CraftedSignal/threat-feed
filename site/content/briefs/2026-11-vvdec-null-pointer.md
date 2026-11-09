---
brief_id: brief-2026-11-09-vvdec-null-pointer
event_id: brief-2026-11-09-vvdec-null-pointer
revision: 1
activity_at: "2026-11-09T19:16:13Z"
title: 'VVdeC: NULL Pointer Dereference in InterPrediction (CVE-2026-124311)'
slug: 2026-11-vvdec-null-pointer
description: A NULL pointer dereference vulnerability exists in the InterPrediction::xPredInterBlk function of the VVdeC (vvdecapp) video decoder, caused by a reference wrap-around in crafted VVC bitstreams.
date: "2026-11-09T19:16:13Z"
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
products:
  - VVdeC (versions through 3.2.1)
cves:
  - id: CVE-2026-124311
    cvss: 5.5
    epss: 0.00121
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/602
---

A NULL pointer dereference vulnerability (CWE-476) has been identified in the VVdeC (vvdecapp) video decoder within the InterPrediction::xPredInterBlk function. The issue is triggered by crafted VVC bitstreams that induce a reference wrap-around. The vulnerability is addressed in commit fb73aca37b48f89814f57edbc8072a37d47bbe06.
