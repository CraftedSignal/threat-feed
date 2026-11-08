---
brief_id: brief-2026-11-08-ibm-api-connect-info-disclosure
event_id: brief-2026-11-08-ibm-api-connect-info-disclosure
revision: 1
activity_at: "2026-11-08T04:51:06Z"
title: 'IBM API Connect: Sensitive information disclosure (CVE-2026-17325)'
slug: 2026-11-ibm-api-connect-info-disclosure
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a vulnerability where improper validation of user-supplied URLs allows remote authenticated attackers to obtain sensitive information.
date: "2026-11-08T04:51:06Z"
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
  - API Connect (12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-17325
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17325
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to improper validation of user-supplied URLs.
