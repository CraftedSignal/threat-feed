---
brief_id: brief-2026-10-29-thimpress-learnpress-auth-bypass
event_id: brief-2026-10-29-thimpress-learnpress-auth-bypass
revision: 1
activity_at: "2026-10-29T13:20:20Z"
title: 'ThimPress LearnPress: Missing authorization vulnerability (CVE-2026-115599)'
slug: 2026-10-thimpress-learnpress-auth-bypass
description: A missing authorization vulnerability in ThimPress LearnPress allows for the exploitation of incorrectly configured access control security levels.
date: "2026-10-29T13:20:20Z"
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
  - cpe:2.3:a:thimpress:learnpress:*:*:*:*:*:*:*:*
vendors:
  - ThimPress
products:
  - LearnPress (n/a through 4.4.11)
cves:
  - id: CVE-2026-115599
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115599
---

A missing authorization vulnerability exists in the ThimPress LearnPress plugin. This flaw allows for the exploitation of incorrectly configured access control security levels. The issue affects LearnPress versions from n/a through 4.4.11.
