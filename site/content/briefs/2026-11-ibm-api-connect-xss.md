---
brief_id: brief-2026-11-07-ibm-api-connect-xss
event_id: brief-2026-11-07-ibm-api-connect-xss
revision: 1
activity_at: "2026-11-07T05:59:55Z"
title: 'IBM API Connect: Cross-site scripting (CVE-2026-16709)'
slug: 2026-11-ibm-api-connect-xss
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 allow a remote authenticated attacker to execute arbitrary JavaScript in the victim's browser due to cross-site scripting.
date: "2026-11-07T05:59:55Z"
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
  - API Connect (10.0.8.0 through 10.0.8.12, 12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-16709
    cvss: 8.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16709
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to a cross-site scripting vulnerability. User-supplied input is not properly neutralized when a web page is updated, allowing a remote authenticated attacker to execute arbitrary JavaScript in the victim's browser.
