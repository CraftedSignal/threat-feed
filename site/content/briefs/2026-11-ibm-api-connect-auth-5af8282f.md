---
brief_id: brief-2026-11-07-ibm-api-connect-auth-5af8282f
event_id: brief-2026-11-07-ibm-api-connect-auth-5af8282f
revision: 1
activity_at: "2026-11-07T06:00:03Z"
title: 'IBM API Connect: Improper authorization information disclosure (CVE-2026-16712)'
slug: 2026-11-ibm-api-connect-auth-5af8282f
description: IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information from other tenants due to improper authorization.
date: "2026-11-07T06:00:03Z"
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
  - IBM API Connect 10.0.8.0 through 10.0.8.12
  - IBM API Connect 12.1.0.0 through 12.1.1.2
cves:
  - id: CVE-2026-16712
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16712
---

IBM API Connect 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to an improper authorization flaw. Identifiers supplied in requests are not sufficiently checked against the user's permissions, which could allow a remote authenticated attacker to access data belonging to other tenants.
