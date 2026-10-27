---
brief_id: brief-2026-10-27-nvidia-physx-oob
event_id: brief-2026-10-27-nvidia-physx-oob
revision: 1
activity_at: "2026-10-27T13:50:26Z"
title: 'NVIDIA PhysX: Out-of-bounds write vulnerability (CVE-2026-47486)'
slug: 2026-10-nvidia-physx-oob
description: NVIDIA PhysX for all platforms contains an out-of-bounds write vulnerability that could lead to code execution, data tampering, denial of service, or information disclosure.
date: "2026-10-27T13:50:26Z"
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
  - cpe:2.3:a:nvidia:physx:*:*:*:*:*:*:*:*
vendors:
  - NVIDIA
products:
  - PhysX
cves:
  - id: CVE-2026-47486
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47486
---

NVIDIA PhysX for all platforms contains a vulnerability where an attacker could cause an out-of-bounds write. A successful exploit of this vulnerability might lead to code execution, data tampering, denial of service, or information disclosure.
