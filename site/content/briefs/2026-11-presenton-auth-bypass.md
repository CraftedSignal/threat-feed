---
brief_id: brief-2026-11-01-presenton-auth-bypass
event_id: brief-2026-11-01-presenton-auth-bypass
revision: 1
activity_at: "2026-11-01T02:07:29Z"
title: 'Presenton: API authentication vulnerability (CVE-2026-120191)'
slug: 2026-11-presenton-auth-bypass
description: A vulnerability in the Presenton API component (up to version 0.9.11-beta) allows for remote, unauthenticated access.
date: "2026-11-01T02:07:29Z"
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
products:
  - Presenton (up to 0.9.11-beta)
cves:
  - id: CVE-2026-120191
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120191
---

A weakness has been identified in Presenton versions up to 0.9.11-beta affecting unknown functionality of the component API. This issue results in missing authentication and can be initiated remotely. A public exploit is available. Upgrading to version 0.9.12-beta (patch 44c8a61122b21f17642d717b0c4d6f2c54c0f180) is recommended to resolve this issue.
