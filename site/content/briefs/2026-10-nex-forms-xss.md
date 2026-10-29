---
brief_id: brief-2026-10-29-nex-forms-xss
event_id: brief-2026-10-29-nex-forms-xss
revision: 1
activity_at: "2026-10-29T13:18:38Z"
title: 'NEX-Forms Ultimate Forms Plugin: Stored Cross-Site Scripting (CVE-2026-96767)'
slug: 2026-10-nex-forms-xss
description: The NEX-Forms - Ultimate Forms Plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'type' parameter in all versions up to and including 9.3.2 due to insufficient input sanitization and output escaping.
date: "2026-10-29T13:18:38Z"
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
  - NEX-Forms – Ultimate Forms Plugin (<= 9.3.2)
cves:
  - id: CVE-2026-96767
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96767
---

The NEX-Forms - Ultimate Forms Plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'type' parameter in all versions up to and including 9.3.2. The vulnerability is caused by insufficient input sanitization and output escaping. Unauthenticated attackers can exploit this to inject arbitrary web scripts that execute when a user accesses an injected page.
