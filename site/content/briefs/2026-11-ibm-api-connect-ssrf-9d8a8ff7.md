---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-9d8a8ff7
event_id: brief-2026-11-07-ibm-api-connect-ssrf-9d8a8ff7
revision: 1
activity_at: "2026-11-07T07:50:30Z"
title: 'IBM API Connect: Server-Side Request Forgery vulnerability (CVE-2026-17298)'
slug: 2026-11-ibm-api-connect-ssrf-9d8a8ff7
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to server-side request forgery.
date: "2026-11-07T07:50:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - id: CVE-2026-17298
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17298
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a Server-Side Request Forgery vulnerability. This vulnerability could allow a remote authenticated attacker to obtain sensitive information. The CVSS v3.1 base score for this vulnerability is 9.9.
