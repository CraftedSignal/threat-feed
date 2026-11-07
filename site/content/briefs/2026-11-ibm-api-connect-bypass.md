---
brief_id: brief-2026-11-07-ibm-api-connect-bypass
event_id: brief-2026-11-07-ibm-api-connect-bypass
revision: 1
activity_at: "2026-11-07T05:49:46Z"
title: 'IBM API Connect: Security restriction bypass (CVE-2026-16920)'
slug: 2026-11-ibm-api-connect-bypass
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to a confused deputy flaw that allows a remote authenticated attacker to bypass security restrictions.
date: "2026-11-07T05:49:46Z"
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
  - id: CVE-2026-16920
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16920
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a confused deputy vulnerability that allows a remote authenticated attacker to bypass security restrictions. This vulnerability has been assigned a CVSS v3.1 base score of 9.9.
