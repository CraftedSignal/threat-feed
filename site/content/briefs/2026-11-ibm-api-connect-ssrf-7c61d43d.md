---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-7c61d43d
event_id: brief-2026-11-07-ibm-api-connect-ssrf-7c61d43d
revision: 1
activity_at: "2026-11-07T06:06:10Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-17288)'
slug: 2026-11-ibm-api-connect-ssrf-7c61d43d
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a server-side request forgery (SSRF) vulnerability that allows a remote authenticated attacker to obtain sensitive information.
date: "2026-11-07T06:06:10Z"
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
  - IBM API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
cves:
  - id: CVE-2026-17288
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17288
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to server-side request forgery (SSRF). This vulnerability may allow a remote authenticated attacker to obtain sensitive information.
