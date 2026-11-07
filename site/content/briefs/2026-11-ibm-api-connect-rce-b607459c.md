---
brief_id: brief-2026-11-07-ibm-api-connect-rce-b607459c
event_id: brief-2026-11-07-ibm-api-connect-rce-b607459c
revision: 1
activity_at: "2026-11-07T09:57:43Z"
title: 'IBM API Connect: Arbitrary JavaScript execution and information disclosure (CVE-2026-17146)'
slug: 2026-11-ibm-api-connect-rce-b607459c
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to a flaw caused by improper input validation, allowing a remote authenticated attacker to execute arbitrary JavaScript and obtain sensitive information.
date: "2026-11-07T09:57:43Z"
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
  - API Connect (10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-17146
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17146
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a vulnerability (CVE-2026-17146) caused by improper input validation. This flaw could allow a remote authenticated attacker to execute arbitrary JavaScript and obtain sensitive information.
