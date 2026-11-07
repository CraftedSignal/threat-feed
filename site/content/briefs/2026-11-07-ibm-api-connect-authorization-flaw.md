---
brief_id: brief-2026-11-07-ibm-api-connect-authorization-flaw
event_id: brief-2026-11-07-ibm-api-connect-authorization-flaw
revision: 1
activity_at: "2026-11-07T06:08:11Z"
title: 'IBM API Connect: Improper authorization flaw (CVE-2026-17319)'
slug: 2026-11-07-ibm-api-connect-authorization-flaw
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain an improper authorization vulnerability. The application relies on client-supplied information to enforce authorization decisions, allowing a remote authenticated attacker to modify tool configurations and cause a denial of service.
date: "2026-11-07T06:08:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - API Connect (12.1.0.0 - 12.1.1.2)
cves:
  - id: CVE-2026-17319
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17319
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to an improper authorization vulnerability (CVE-2026-17319). By relying on client-supplied information to manage authorization, the application permits authenticated remote attackers to perform unauthorized configuration changes that result in service disruption.
