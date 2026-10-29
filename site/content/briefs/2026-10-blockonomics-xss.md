---
brief_id: brief-2026-10-29-blockonomics-xss
event_id: brief-2026-10-29-blockonomics-xss
revision: 1
activity_at: "2026-10-29T17:40:25Z"
title: 'Blockonomics: Unauthenticated Cross-Site Scripting (CVE-2026-61993)'
slug: 2026-10-blockonomics-xss
description: Blockonomics version 3.11.0 is affected by an unauthenticated Cross-Site Scripting (XSS) vulnerability.
date: "2026-10-29T17:40:25Z"
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
  - cpe:2.3:a:blockonomics:blockonomics:*:*:*:*:*:*:*:*
vendors:
  - Blockonomics
products:
  - Blockonomics (3.11.0)
cves:
  - id: CVE-2026-61993
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61993
---

Blockonomics version 3.11.0 contains an unauthenticated Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-61993. The CVSS v3.1 base score for this vulnerability is 7.1.
