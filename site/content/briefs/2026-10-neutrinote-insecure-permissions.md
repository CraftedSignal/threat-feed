---
brief_id: brief-2026-10-30-neutrinote-insecure-permissions
event_id: brief-2026-10-30-neutrinote-insecure-permissions
revision: 1
activity_at: "2026-10-30T19:38:23Z"
title: 'AppML neutriNote CE: Insecure file permissions in autosave component (CVE-2026-107055)'
slug: 2026-10-neutrinote-insecure-permissions
description: A vulnerability in the autosave component of AppML neutriNote CE version 1387 allows unauthorized attackers to write arbitrary files.
date: "2026-10-30T19:38:23Z"
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
  - cpe:2.3:a:appml:neutrinote:1387:*:*:*:*:*:*:*
vendors:
  - AppML
products:
  - neutriNote CE (versionCode 1387)
cves:
  - id: CVE-2026-107055
    cvss: 7.5
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107055
---

CVE-2026-107055 identifies an insecure permissions flaw within the autosave component of AppML neutriNote CE, specifically in versionCode 1387. This vulnerability allows unauthorized attackers to write arbitrary files.
