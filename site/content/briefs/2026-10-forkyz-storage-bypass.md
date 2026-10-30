---
brief_id: brief-2026-10-30-forkyz-storage-bypass
event_id: brief-2026-10-30-forkyz-storage-bypass
revision: 1
activity_at: "2026-10-30T23:46:36Z"
title: 'Forkyz: Storage settings modification vulnerability (CVE-2026-107049)'
slug: 2026-10-forkyz-storage-bypass
description: Forkyz versionCode 8500000 allows attackers to arbitrarily change another user's storage settings via supplying a crafted URI string.
date: "2026-10-30T23:46:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:forkyz:forkyz:*:*:*:*:*:*:*:*
vendors:
  - Forkyz
products:
  - Forkyz (versionCode 8500000)
cves:
  - id: CVE-2026-107049
    cvss: 7.5
    epss: 0.00166
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107049
---

Forkyz versionCode 8500000 contains a vulnerability (CVE-2026-107049) that allows attackers to arbitrarily change another user's storage settings by supplying a crafted URI string.

## References
- https://nvd.nist.gov/vuln/detail/CVE-2026-107049
