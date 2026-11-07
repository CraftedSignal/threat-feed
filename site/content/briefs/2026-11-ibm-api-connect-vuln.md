---
brief_id: brief-2026-11-07-ibm-api-connect-vuln
event_id: brief-2026-11-07-ibm-api-connect-vuln
revision: 1
activity_at: "2026-11-07T05:54:14Z"
title: 'IBM API Connect: Sensitive information disclosure (CVE-2026-17329)'
slug: 2026-11-ibm-api-connect-vuln
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to a remote information disclosure flaw caused by improper validation of endpoint URLs.
date: "2026-11-07T05:54:14Z"
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
  - id: CVE-2026-17329
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17329
---

IBM API Connect 12.1.0.0 through 12.1.1.2 contains a vulnerability that could allow a remote attacker to obtain sensitive information due to improper validation of endpoint URLs. The vulnerability has a CVSS v3.1 base score of 9.3.
