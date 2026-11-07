---
brief_id: brief-2026-11-07-ibm-api-connect-bola-65f79a78
event_id: brief-2026-11-07-ibm-api-connect-bola-65f79a78
revision: 1
activity_at: "2026-11-07T09:57:53Z"
title: 'IBM API Connect: Broken Object-Level Authorization (CVE-2026-17338)'
slug: 2026-11-ibm-api-connect-bola-65f79a78
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a broken object-level authorization vulnerability that could allow a remote authenticated attacker to obtain sensitive information.
date: "2026-11-07T09:57:53Z"
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
  - id: CVE-2026-17338
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17338
---

IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to broken object-level authorization. This vulnerability has a CVSS v3.1 base score of 9.1.
