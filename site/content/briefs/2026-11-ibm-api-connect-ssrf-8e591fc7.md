---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-8e591fc7
event_id: brief-2026-11-07-ibm-api-connect-ssrf-8e591fc7
revision: 1
activity_at: "2026-11-07T07:52:26Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-17289)'
slug: 2026-11-ibm-api-connect-ssrf-8e591fc7
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 allow a remote authenticated attacker to obtain sensitive information due to server-side request forgery.
date: "2026-11-07T07:52:26Z"
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
  - id: CVE-2026-17289
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17289
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to server-side request forgery (SSRF). This flaw allows a remote authenticated attacker to obtain sensitive information. The vulnerability has a CVSS v3.1 base score of 7.7.
