---
brief_id: brief-2026-10-30-canvoki-insecure-permissions
event_id: brief-2026-10-30-canvoki-insecure-permissions
revision: 1
activity_at: "2026-10-30T19:37:04Z"
title: 'canvoki: Unauthorized automated action triggering (CVE-2026-107017)'
slug: 2026-10-canvoki-insecure-permissions
description: An insecure permission vulnerability in the ShortcutDispatchActivity component of canvoki version 14 allows unauthorized attackers to arbitrarily trigger another user's configured automated actions.
date: "2026-10-30T19:37:04Z"
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
  - cpe:2.3:a:canvoki:canvoki:*:*:*:*:*:*:*:*
vendors:
  - canvoki
products:
  - canvoki (versionCode 14)
cves:
  - id: CVE-2026-107017
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107017
---

CVE-2026-107017 identifies an insecure permission vulnerability in the ShortcutDispatchActivity component of canvoki versionCode 14. This flaw allows unauthorized attackers to arbitrarily trigger automated actions configured by other users. The vulnerability has a CVSS v3.1 base score of 9.1.
