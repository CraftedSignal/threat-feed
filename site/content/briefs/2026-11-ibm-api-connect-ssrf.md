---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf
event_id: brief-2026-11-07-ibm-api-connect-ssrf
revision: 1
activity_at: "2026-11-07T05:49:38Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-16918)'
slug: 2026-11-ibm-api-connect-ssrf
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a server-side request forgery vulnerability that could allow a remote attacker to access internal network resources.
date: "2026-11-07T05:49:38Z"
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
  - id: CVE-2026-16918
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16918
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to a server-side request forgery (SSRF) vulnerability. This vulnerability could allow a remote attacker to access internal network resources. The vulnerability is assigned a CVSS v3.1 base score of 9.3.
