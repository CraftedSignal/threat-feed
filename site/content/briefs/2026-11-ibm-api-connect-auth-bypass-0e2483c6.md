---
brief_id: brief-2026-11-07-ibm-api-connect-auth-bypass-0e2483c6
event_id: brief-2026-11-07-ibm-api-connect-auth-bypass-0e2483c6
revision: 1
activity_at: "2026-11-07T05:54:03Z"
title: 'IBM API Connect: Authentication bypass via alternate path (CVE-2026-17313)'
slug: 2026-11-ibm-api-connect-auth-bypass-0e2483c6
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain an authentication bypass vulnerability that allows a remote attacker to obtain sensitive information and take control of gateway configuration.
date: "2026-11-07T05:54:03Z"
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
  - id: CVE-2026-17313
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17313
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to an authentication bypass vulnerability via an alternate path. This flaw may allow a remote attacker to obtain sensitive information and take control of gateway configuration.
