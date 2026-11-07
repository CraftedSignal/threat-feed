---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-2f65d992
event_id: brief-2026-11-07-ibm-api-connect-ssrf-2f65d992
revision: 1
activity_at: "2026-11-07T07:52:15Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-17287)'
slug: 2026-11-ibm-api-connect-ssrf-2f65d992
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to server-side request forgery (SSRF), allowing a remote authenticated attacker to obtain sensitive information.
date: "2026-11-07T07:52:15Z"
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
  - id: CVE-2026-17287
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17287
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a server-side request forgery (SSRF) vulnerability. Due to insufficient validation of user-supplied addresses, an authenticated remote attacker can cause the server to send requests to unintended destinations and return the results, potentially leading to the disclosure of sensitive information.
