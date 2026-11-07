---
brief_id: brief-2026-11-07-ibm-api-connect-auth-bypass
event_id: brief-2026-11-07-ibm-api-connect-auth-bypass
revision: 1
activity_at: "2026-11-07T05:49:19Z"
title: 'IBM API Connect: Improper authentication vulnerability (CVE-2026-16720)'
slug: 2026-11-ibm-api-connect-auth-bypass
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to improper authentication, which could allow a remote attacker to obtain valid access tokens for other users.
date: "2026-11-07T05:49:19Z"
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
  - API Connect (10.0.8.0 through 10.0.8.12)
  - API Connect (12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-16720
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16720
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain an improper authentication vulnerability. Authentication against a connected directory service is not sufficiently enforced, which could allow a remote attacker to assume another user's identity by obtaining valid access tokens. The CVSS v3.1 base score for this vulnerability is 9.8.
