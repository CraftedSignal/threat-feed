---
brief_id: brief-2026-11-07-ibm-api-connect-xss-d83cb1cf
event_id: brief-2026-11-07-ibm-api-connect-xss-d83cb1cf
revision: 1
activity_at: "2026-11-07T06:02:51Z"
title: 'IBM API Connect: Cross-site scripting vulnerability (CVE-2026-17190)'
slug: 2026-11-ibm-api-connect-xss-d83cb1cf
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a cross-site scripting vulnerability (CVE-2026-17190) that allows a remote authenticated attacker to execute arbitrary JavaScript due to insufficient sanitization of HTML content supplied by a provider.
date: "2026-11-07T06:02:51Z"
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
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
cves:
  - id: CVE-2026-17190
    cvss: 8.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17190
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to a cross-site scripting vulnerability identified as CVE-2026-17190. The vulnerability exists because HTML content supplied by a provider is not sufficiently sanitized before display, which could allow script content to run in the user's browser.

## Technical Details

A remote authenticated attacker can leverage this vulnerability to execute arbitrary JavaScript.
