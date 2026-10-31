---
brief_id: brief-2026-10-31-pypdf-memory-exhaustion-1402e87f
event_id: brief-2026-10-31-pypdf-memory-exhaustion-1402e87f
revision: 2
activity_at: "2026-10-31T21:22:42Z"
revision_history:
  - revision: 2
    at: "2026-10-31T21:22:42Z"
    checksum: sha256:1e408280778b0de89231abb3cffd5a3ccdbc8c5ad5fb1531fe05809f0511ad3b
    summary: severity → high; added CVE-2026-119206
    changed_fields:
      - cves
      - lastmod
      - references
      - severity
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-42gh-23hr-vphw
title: 'pypdf: Potential large memory usage when parsing cross-reference streams (CVE-2026-119209)'
slug: 2026-10-pypdf-memory-exhaustion-1402e87f
description: The pypdf library may experience large memory usage when parsing crafted PDF files containing cross-reference streams.
date: "2026-10-31T09:15:19Z"
lastmod: "2026-10-31T21:20:56Z"
type: advisory
types:
  - advisory
severities:
  - high
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
  - id: CVE-2026-119206
    epss: 0.00304
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-x3rh-gjgm-fmqc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119209
  - https://github.com/py-pdf/pypdf/pull/4269
  - https://github.com/py-pdf/pypdf/releases/tag/6.21.3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119206
  - https://github.com/py-pdf/pypdf/pull/4251
  - https://github.com/advisories/GHSA-42gh-23hr-vphw
updates:
  - at: "2026-10-31T21:20:56Z"
    level: L2
    summary: severity → high; added CVE-2026-119206
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-42gh-23hr-vphw
---

An attacker can craft a PDF that leads to large memory usage when parsed by pypdf. This requires opening a file with cross-reference streams. This issue has been addressed in pypdf version 6.21.3.
