---
brief_id: brief-2026-11-07-ibm-api-connect-auth-bypass-714ce6e5
event_id: brief-2026-11-07-ibm-api-connect-auth-bypass-714ce6e5
revision: 1
activity_at: "2026-11-07T06:07:59Z"
title: 'IBM API Connect: Improper authorization information disclosure (CVE-2026-17318)'
slug: 2026-11-ibm-api-connect-auth-bypass-714ce6e5
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain an improper authorization vulnerability that could allow a remote authenticated attacker to obtain sensitive information.
date: "2026-11-07T06:07:59Z"
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
  - API Connect (10.0.8.0 through 10.0.8.12)
  - API Connect (12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-17318
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17318
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to an improper authorization vulnerability (CVE-2026-17318). This issue may allow a remote authenticated attacker to obtain sensitive information. The vulnerability has a CVSS v3.1 base score of 7.7.
