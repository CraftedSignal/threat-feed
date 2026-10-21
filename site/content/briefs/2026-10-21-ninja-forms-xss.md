---
brief_id: brief-2026-10-21-ninja-forms-xss
event_id: brief-2026-10-21-ninja-forms-xss
revision: 1
activity_at: "2026-10-21T08:42:23Z"
title: 'Kevin Stover Ninja Forms: Stored Cross-site Scripting (CVE-2026-110899)'
slug: 2026-10-21-ninja-forms-xss
description: A stored cross-site scripting (XSS) vulnerability exists in the Kevin Stover Ninja Forms plugin due to improper neutralization of input during web page generation.
date: "2026-10-21T08:42:23Z"
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
  - cpe:2.3:a:kevin_stover:ninja_forms:*:*:*:*:*:*:*:*
vendors:
  - Kevin Stover
products:
  - Ninja Forms (n/a through 3.15.5)
cves:
  - id: CVE-2026-110899
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110899
---

CVE-2026-110899 is a stored cross-site scripting (XSS) vulnerability in the Kevin Stover Ninja Forms plugin. The vulnerability is caused by improper neutralization of input during web page generation. This issue affects Ninja Forms versions up to and including 3.15.5.

## Impact
Successful exploitation allows for stored XSS.
