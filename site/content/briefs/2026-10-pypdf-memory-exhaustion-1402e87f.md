---
brief_id: brief-2026-10-31-pypdf-memory-exhaustion-1402e87f
event_id: brief-2026-10-31-pypdf-memory-exhaustion-1402e87f
revision: 1
activity_at: "2026-10-31T09:15:19Z"
title: 'pypdf: Potential large memory usage when parsing cross-reference streams (CVE-2026-119209)'
slug: 2026-10-pypdf-memory-exhaustion-1402e87f
description: The pypdf library may experience large memory usage when parsing crafted PDF files containing cross-reference streams.
date: "2026-10-31T09:15:19Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:pypdf_project:pypdf:*:*:*:*:*:*:*:*
products:
  - pypdf (< 6.21.3)
cves:
  - id: CVE-2026-119209
    cvss: 5.5
    epss: 0.00319
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-x3rh-gjgm-fmqc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119209
  - https://github.com/py-pdf/pypdf/pull/4269
  - https://github.com/py-pdf/pypdf/releases/tag/6.21.3
---

An attacker can craft a PDF that leads to large memory usage when parsed by pypdf. This requires opening a file with cross-reference streams. This issue has been addressed in pypdf version 6.21.3.
