---
brief_id: brief-2026-11-08-tenda-ac19-buffer-overflow
event_id: brief-2026-11-08-tenda-ac19-buffer-overflow
revision: 1
activity_at: "2026-11-08T00:44:48Z"
title: 'Tenda AC19: Heap-based buffer overflow in saveParentControlInfo (CVE-2026-123966)'
slug: 2026-11-tenda-ac19-buffer-overflow
description: A heap-based buffer overflow vulnerability exists in Tenda AC19 firmware version 16.03.10.07, located in the saveParentControlInfo function within the /goform/saveParentControlInfo file.
date: "2026-11-08T00:44:48Z"
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
cpes:
  - cpe:2.3:a:tenda:ac19:*:*:*:*:*:*:*:*
vendors:
  - Tenda
products:
  - AC19 (16.03.10.07)
cves:
  - id: CVE-2026-123966
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123966
---

A vulnerability has been identified in Tenda AC19 (firmware 16.03.10.07). The function saveParentControlInfo in /goform/saveParentControlInfo is susceptible to a heap-based buffer overflow when the deviceId argument is manipulated. This attack can be performed remotely, and the exploit has been publicly disclosed.
