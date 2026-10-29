---
brief_id: brief-2026-10-29-wordpress-plugin-rce
event_id: brief-2026-10-29-wordpress-plugin-rce
revision: 1
activity_at: "2026-10-29T15:39:40Z"
title: 'Frontend Dashboard and ProfileGrid: PHP Object Injection (CVE-2026-103693)'
slug: 2026-10-wordpress-plugin-rce
description: Frontend Dashboard and ProfileGrid WordPress plugins allow unauthenticated users to perform PHP object injection via user metadata, potentially leading to arbitrary file write and remote code execution.
date: "2026-10-29T15:39:40Z"
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
  - Frontend Dashboard (< 3.0.5)
  - ProfileGrid (< 6.0.0.5)
cves:
  - id: CVE-2026-103693
    cvss: 9
    epss: 0.00236
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103693
---

Frontend Dashboard (before 3.0.5) and ProfileGrid (before 6.0.0.5) WordPress plugins contain a vulnerability where unauthenticated users can store a serialized PHP object in user metadata. This object is deserialized when a public profile is viewed, enabling PHP object injection. This can lead to arbitrary file write and potential remote code execution.
