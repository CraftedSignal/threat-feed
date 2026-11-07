---
brief_id: brief-2026-11-07-ibm-api-connect-bola-840f7577
event_id: brief-2026-11-07-ibm-api-connect-bola-840f7577
revision: 1
activity_at: "2026-11-07T06:07:39Z"
title: 'IBM API Connect: Broken object-level authorization (CVE-2026-17311)'
slug: 2026-11-ibm-api-connect-bola-840f7577
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to a broken object-level authorization flaw that allows a remote authenticated attacker to modify application API subscriptions.
date: "2026-11-07T06:07:39Z"
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
  - id: CVE-2026-17311
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17311
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a broken object-level authorization vulnerability, identified as CVE-2026-17311. This flaw allows a remote authenticated attacker to modify application API subscriptions.
