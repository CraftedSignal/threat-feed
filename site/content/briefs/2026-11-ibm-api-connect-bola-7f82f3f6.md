---
brief_id: brief-2026-11-07-ibm-api-connect-bola-7f82f3f6
event_id: brief-2026-11-07-ibm-api-connect-bola-7f82f3f6
revision: 1
activity_at: "2026-11-07T07:51:56Z"
title: 'IBM API Connect: Broken object-level authorization (CVE-2026-17282)'
slug: 2026-11-ibm-api-connect-bola-7f82f3f6
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 allow a remote authenticated attacker to obtain sensitive information due to broken object-level authorization.
date: "2026-11-07T07:51:56Z"
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
vendors:
  - IBM
products:
  - API Connect 10.0.8.0 through 10.0.8.12
  - API Connect 12.1.0.0 through 12.1.1.2
cves:
  - id: CVE-2026-17282
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17282
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to broken object-level authorization (CVE-2026-17282).
