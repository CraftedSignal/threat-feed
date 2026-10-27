---
brief_id: brief-2026-10-27-node-tesseract-rce
event_id: brief-2026-10-27-node-tesseract-rce
revision: 1
activity_at: "2026-10-27T18:01:51Z"
title: 'node-tesseract: OS command injection in lib/tesseract.js (CVE-2026-117511)'
slug: 2026-10-node-tesseract-rce
description: A vulnerability exists in desmondmorris node-tesseract up to 0.2.7 where the process function in lib/tesseract.js is susceptible to OS command injection via the image argument.
date: "2026-10-27T18:01:51Z"
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
  - cpe:2.3:a:desmondmorris:node_tesseract:*:*:*:*:*:*:*:*
vendors:
  - desmondmorris
products:
  - node-tesseract (<= 0.2.7)
cves:
  - id: CVE-2026-117511
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117511
---

A vulnerability has been found in desmondmorris node-tesseract up to 0.2.7. The process function in lib/tesseract.js, part of the Command Builder component, is affected by OS command injection through manipulation of the image argument. The attack can be executed remotely. The exploit has been disclosed to the public, and the project has not responded to an early issue report.
