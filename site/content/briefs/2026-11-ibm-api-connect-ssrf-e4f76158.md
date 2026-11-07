---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-e4f76158
event_id: brief-2026-11-07-ibm-api-connect-ssrf-e4f76158
revision: 1
activity_at: "2026-11-07T07:51:19Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-18836)'
slug: 2026-11-ibm-api-connect-ssrf-e4f76158
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to server-side request forgery (SSRF), which may allow a remote attacker to obtain sensitive information.
date: "2026-11-07T07:51:19Z"
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
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
cves:
  - id: CVE-2026-18836
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18836
---

IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information due to server-side request forgery. The affected component can be made to send requests to unintended destinations and return the response to the attacker.
