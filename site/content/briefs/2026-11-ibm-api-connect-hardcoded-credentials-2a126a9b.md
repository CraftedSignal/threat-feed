---
brief_id: brief-2026-11-07-ibm-api-connect-hardcoded-credentials-2a126a9b
event_id: brief-2026-11-07-ibm-api-connect-hardcoded-credentials-2a126a9b
revision: 1
activity_at: "2026-11-07T07:51:02Z"
title: 'IBM API Connect: Hard-coded credentials remote administrative access (CVE-2026-17403)'
slug: 2026-11-ibm-api-connect-hardcoded-credentials-2a126a9b
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain hard-coded credentials that allow a remote attacker to gain full administrative control.
date: "2026-11-07T07:51:02Z"
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
  - API Connect (10.0.8.0-10.0.8.12)
  - API Connect (12.1.0.0-12.1.1.2)
cves:
  - id: CVE-2026-17403
    cvss: 9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17403
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a vulnerability involving the use of hard-coded credentials. This vulnerability could allow a remote attacker to gain full administrative control. The CVSS v3.1 base score for this vulnerability is 9.0.
