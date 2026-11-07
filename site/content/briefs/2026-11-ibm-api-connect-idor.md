---
brief_id: brief-2026-11-07-ibm-api-connect-idor
event_id: brief-2026-11-07-ibm-api-connect-idor
revision: 1
activity_at: "2026-11-07T06:02:10Z"
title: 'IBM API Connect: Insecure direct object reference (CVE-2026-17129)'
slug: 2026-11-ibm-api-connect-idor
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain an insecure direct object reference vulnerability that allows remote authenticated attackers to obtain sensitive information and cause a denial of service.
date: "2026-11-07T06:02:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - id: CVE-2026-17129
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17129
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to an Insecure Direct Object Reference (IDOR) vulnerability. A remote authenticated attacker can exploit this to obtain sensitive information and cause a denial of service.

## Impact
Successful exploitation allows unauthorized disclosure of sensitive information and denial of service.
