---
brief_id: brief-2026-11-09-wedocs-auth-bypass
event_id: brief-2026-11-09-wedocs-auth-bypass
revision: 1
activity_at: "2026-11-09T13:48:49Z"
title: 'weDevs weDocs: Missing authorization vulnerability (CVE-2026-121760)'
slug: 2026-11-wedocs-auth-bypass
description: The weDevs weDocs plugin (versions up to 2.6.1) contains a missing authorization vulnerability related to incorrectly configured access control security levels.
date: "2026-11-09T13:48:49Z"
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
  - cpe:2.3:a:wedevs:wedocs:*:*:*:*:*:*:*:*
vendors:
  - weDevs
products:
  - weDocs (n/a through 2.6.1)
cves:
  - id: CVE-2026-121760
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121760
---

The weDevs weDocs plugin, from version n/a through 2.6.1, is affected by a Missing Authorization vulnerability. This flaw allows for the exploitation of incorrectly configured access control security levels.
