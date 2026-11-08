---
brief_id: brief-2026-11-08-melapress-role-editor-auth
event_id: brief-2026-11-08-melapress-role-editor-auth
revision: 1
activity_at: "2026-11-08T19:35:43Z"
title: 'Melapress Role Editor: Missing Authorization vulnerability (CVE-2026-109899)'
slug: 2026-11-melapress-role-editor-auth
description: A missing authorization vulnerability in Melapress Role Editor (versions n/a through 1.3.0) allows exploiting incorrectly configured access control security levels.
date: "2026-11-08T19:35:43Z"
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
  - cpe:2.3:a:melapress:role_editor:*:*:*:*:*:*:*:*
vendors:
  - Melapress
products:
  - Melapress Role Editor (n/a through 1.3.0)
cves:
  - id: CVE-2026-109899
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109899
---

A Missing Authorization vulnerability has been identified in Melapress Role Editor (melapress-role-editor). The vulnerability affects versions from n/a through 1.3.0 and allows for the exploitation of incorrectly configured access control security levels.
