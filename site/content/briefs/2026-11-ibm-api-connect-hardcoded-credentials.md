---
brief_id: brief-2026-11-07-ibm-api-connect-hardcoded-credentials
event_id: brief-2026-11-07-ibm-api-connect-hardcoded-credentials
revision: 1
activity_at: "2026-11-07T05:55:35Z"
title: 'IBM API Connect: Hard-coded credentials remote administrative access (CVE-2026-17360)'
slug: 2026-11-ibm-api-connect-hardcoded-credentials
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain hard-coded credentials that could allow a remote attacker to gain full administrative control.
date: "2026-11-07T05:55:35Z"
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
  - id: CVE-2026-17360
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17360
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are affected by a vulnerability involving the use of hard-coded credentials. This could allow a remote attacker to gain full administrative control.
