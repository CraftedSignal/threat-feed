---
brief_id: brief-2026-11-07-ibm-api-connect-redirect-80639435
event_id: brief-2026-11-07-ibm-api-connect-redirect-80639435
revision: 1
activity_at: "2026-11-07T06:06:34Z"
title: 'IBM API Connect: Account takeover via OAuth 2.0 open redirect (CVE-2026-17291)'
slug: 2026-11-ibm-api-connect-redirect-80639435
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain an open redirect vulnerability during OAuth 2.0 sign-in, which may allow a remote authenticated attacker to have authentication results sent to an attacker-controlled location, potentially leading to account takeover.
date: "2026-11-07T06:06:34Z"
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
  - id: CVE-2026-17291
    cvss: 8.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17291
---
