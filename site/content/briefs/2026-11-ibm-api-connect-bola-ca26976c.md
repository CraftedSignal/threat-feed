---
brief_id: brief-2026-11-07-ibm-api-connect-bola-ca26976c
event_id: brief-2026-11-07-ibm-api-connect-bola-ca26976c
revision: 1
activity_at: "2026-11-07T06:00:55Z"
title: 'IBM API Connect: Broken Object-Level Authorization (CVE-2026-16717)'
slug: 2026-11-ibm-api-connect-bola-ca26976c
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to broken object-level authorization, which may allow a remote authenticated attacker to obtain sensitive information.
date: "2026-11-07T06:00:55Z"
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
  - id: CVE-2026-16717
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16717
---

IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to broken object-level authorization.
