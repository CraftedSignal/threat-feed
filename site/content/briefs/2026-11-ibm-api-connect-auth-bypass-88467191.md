---
brief_id: brief-2026-11-07-ibm-api-connect-auth-bypass-88467191
event_id: brief-2026-11-07-ibm-api-connect-auth-bypass-88467191
revision: 1
activity_at: "2026-11-07T06:02:20Z"
title: 'IBM API Connect: Security restriction bypass (CVE-2026-17172)'
slug: 2026-11-ibm-api-connect-auth-bypass-88467191
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain an improper authentication vulnerability. A remote authenticated attacker may impersonate another party due to insufficient verification of client-supplied information.
date: "2026-11-07T06:02:20Z"
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
  - API Connect (10.0.8.0 through 10.0.8.12, 12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-17172
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17172
---

IBM API Connect (versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2) is vulnerable to an improper authentication flaw. This allows a remote authenticated attacker to bypass security restrictions by impersonating another party, as the system does not sufficiently verify information supplied by the client.
