---
brief_id: brief-2026-11-07-ibm-api-connect-auth-bypass-98f35000
event_id: brief-2026-11-07-ibm-api-connect-auth-bypass-98f35000
revision: 1
activity_at: "2026-11-07T05:56:57Z"
title: 'IBM API Connect: Improper authentication vulnerability (CVE-2026-18838)'
slug: 2026-11-ibm-api-connect-auth-bypass-98f35000
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain an improper authentication vulnerability that allows a remote attacker to obtain sensitive information and modify API configurations.
date: "2026-11-07T05:56:57Z"
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
  - id: CVE-2026-18838
    cvss: 9.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18838
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to a vulnerability due to improper authentication. Identity information provided in requests is not sufficiently verified, allowing remote attackers to impersonate other users. This can lead to the unauthorized disclosure of sensitive information and the modification of API configurations.
