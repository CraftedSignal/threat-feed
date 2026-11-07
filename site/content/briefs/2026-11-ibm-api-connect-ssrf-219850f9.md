---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-219850f9
event_id: brief-2026-11-07-ibm-api-connect-ssrf-219850f9
revision: 1
activity_at: "2026-11-07T07:50:05Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-17131)'
slug: 2026-11-ibm-api-connect-ssrf-219850f9
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a server-side request forgery (SSRF) vulnerability that may allow a remote attacker to obtain sensitive information.
date: "2026-11-07T07:50:05Z"
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
  - API Connect (12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-17131
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17131
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are affected by a server-side request forgery (SSRF) vulnerability. This flaw allows a remote attacker to bypass restrictions on outbound requests, enabling the server to contact unintended destinations and return the response to the attacker.
