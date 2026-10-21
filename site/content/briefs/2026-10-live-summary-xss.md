---
brief_id: brief-2026-10-21-live-summary-xss
event_id: brief-2026-10-21-live-summary-xss
revision: 1
activity_at: "2026-10-21T11:19:46Z"
title: 'Live Summary for Gravity Forms: Reflected Cross-site Scripting (CVE-2026-110884)'
slug: 2026-10-live-summary-xss
description: The Live Summary for Gravity Forms plugin for WordPress is affected by a Reflected Cross-site Scripting (XSS) vulnerability.
date: "2026-10-21T11:19:46Z"
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
  - Live Summary for Gravity Forms (n/a through 1.2.10)
cves:
  - id: CVE-2026-110884
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110884
---

The "Live Summary for Gravity Forms" plugin is affected by an Improper Neutralization of Input During Web Page Generation vulnerability, resulting in Reflected XSS. This vulnerability affects versions from n/a through 1.2.10.
