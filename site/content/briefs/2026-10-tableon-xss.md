---
brief_id: brief-2026-10-29-tableon-xss
event_id: brief-2026-10-29-tableon-xss
revision: 1
activity_at: "2026-10-29T13:20:31Z"
title: 'PluginUs.Net TableOn: Reflected Cross-Site Scripting (CVE-2026-115611)'
slug: 2026-10-tableon-xss
description: The PluginUs.Net TableOn WordPress plugin contains an improper neutralization of input vulnerability leading to Reflected Cross-site Scripting.
date: "2026-10-29T13:20:31Z"
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
products:
  - TableOn (n/a - 1.0.7)
cves:
  - id: CVE-2026-115611
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115611
---

The PluginUs.Net TableOn posts-table-filterable plugin is affected by a vulnerability involving improper neutralization of input during web page generation. This allows for Reflected Cross-site Scripting (XSS). This issue affects all versions of TableOn from n/a through 1.0.7.
