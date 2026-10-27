---
brief_id: brief-2026-10-27-autodesk-fusion-xss
event_id: brief-2026-10-27-autodesk-fusion-xss
revision: 1
activity_at: "2026-10-27T18:02:06Z"
title: 'Autodesk Fusion: Reflected Cross-site Scripting (CVE-2026-102637)'
slug: 2026-10-autodesk-fusion-xss
description: A Reflected Cross-site Scripting (XSS) vulnerability exists in the Autodesk Fusion desktop application, triggered by a maliciously crafted HTML payload in the documentName parameter of a Fusion protocol URL.
date: "2026-10-27T18:02:06Z"
lastmod: "2026-10-27T18:02:19Z"
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
  - cpe:2.3:a:autodesk:fusion:*:*:*:*:*:*:*:*
vendors:
  - Autodesk
products:
  - Fusion
cves:
  - id: CVE-2026-102637
    cvss: 7.1
    kev_status: "false"
  - id: CVE-2026-102638
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102637
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102638
updates:
  - at: "2026-10-27T18:02:19Z"
    level: L2
    summary: added CVE-2026-102638
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102638
---

A Reflected Cross-site Scripting (XSS) vulnerability in the Autodesk Fusion desktop application can be triggered when a user invokes a Fusion protocol URL containing a maliciously crafted HTML payload in the 'documentName' parameter. 

## Impact
A malicious actor may leverage this vulnerability to read local files or execute arbitrary code in the context of the current Autodesk Fusion process.
