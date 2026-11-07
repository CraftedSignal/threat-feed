---
brief_id: brief-2026-11-07-ibm-api-connect-redirect
event_id: brief-2026-11-07-ibm-api-connect-redirect
revision: 1
activity_at: "2026-11-07T05:51:44Z"
title: 'IBM API Connect: Open redirect account takeover (CVE-2026-17297)'
slug: 2026-11-ibm-api-connect-redirect
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to an open redirect during sign-in, which may allow a remote attacker to perform an account takeover.
date: "2026-11-07T05:51:44Z"
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
  - id: CVE-2026-17297
    cvss: 9.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17297
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain an open redirect vulnerability. The redirect address used during the sign-in process is not sufficiently validated, which could allow authentication results to be sent to an attacker-controlled location. This vulnerability carries a CVSS v3.1 base score of 9.6.
