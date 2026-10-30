---
brief_id: brief-2026-10-30-projectmaxs-maxs-main-insecure-permissions
event_id: brief-2026-10-30-projectmaxs-maxs-main-insecure-permissions
revision: 1
activity_at: "2026-10-30T19:38:07Z"
title: 'ProjectMAXS MAXS Main: Insecure permissions (CVE-2026-107044)'
slug: 2026-10-projectmaxs-maxs-main-insecure-permissions
description: An insecure permission vulnerability in ProjectMAXS MAXS Main version 0.5.19 (versionCode 19) allows unauthorized attackers to arbitrarily manipulate the app's MAXS command/transport mechanism.
date: "2026-10-30T19:38:07Z"
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
vendors:
  - ProjectMAXS
products:
  - MAXS Main (0.5.19)
cves:
  - id: CVE-2026-107044
    cvss: 7.5
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107044
---

ProjectMAXS MAXS Main version 0.5.19 (versionCode 19) contains an insecure permission vulnerability that allows unauthorized attackers to arbitrarily manipulate the application's MAXS command/transport mechanism. This vulnerability carries a CVSS v3.1 base score of 7.5.
