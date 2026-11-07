---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-6def7b9c
event_id: brief-2026-11-07-ibm-api-connect-ssrf-6def7b9c
revision: 1
activity_at: "2026-11-07T06:04:52Z"
title: 'IBM API Connect: Server-side request forgery vulnerability (CVE-2026-17228)'
slug: 2026-11-ibm-api-connect-ssrf-6def7b9c
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a server-side request forgery (SSRF) vulnerability that allows a remote authenticated attacker to bypass destination restrictions and retrieve content from unintended resources.
date: "2026-11-07T06:04:52Z"
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
  - API Connect (12.1.0.0 - 12.1.1.2)
cves:
  - id: CVE-2026-17228
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17228
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to a server-side request forgery (SSRF) vulnerability. This flaw allows a remote authenticated attacker to bypass destination restrictions on outbound requests, potentially enabling the retrieval of content from unintended resources.
