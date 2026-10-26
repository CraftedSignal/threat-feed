---
brief_id: brief-2026-10-26-yoosee-gm8135s-secure-boot
event_id: brief-2026-10-26-yoosee-gm8135s-secure-boot
revision: 1
activity_at: "2026-10-26T05:34:43Z"
title: 'Yoosee GM8135S Camera: Improper cryptographic signature verification (CVE-2026-116116)'
slug: 2026-10-yoosee-gm8135s-secure-boot
description: A vulnerability in the Secure Boot component of the Yoosee GM8135S Camera (firmware 21.00.01.36) allows for improper verification of cryptographic signatures via local manipulation.
date: "2026-10-26T05:34:43Z"
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
  - cpe:2.3:a:yoosee:gm8135s_camera:*:*:*:*:*:*:*:*
vendors:
  - Yoosee
products:
  - GM8135S Camera (21.00.01.36)
cves:
  - id: CVE-2026-116116
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116116
---

A vulnerability exists in the Secure Boot component of the Yoosee GM8135S Camera, firmware version 21.00.01.36. The flaw results in improper verification of cryptographic signatures. Exploitation requires local access. The vendor was contacted but did not respond. Public exploit code is available.
