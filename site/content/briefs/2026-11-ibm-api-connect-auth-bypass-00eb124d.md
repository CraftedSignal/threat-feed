---
brief_id: brief-2026-11-08-ibm-api-connect-auth-bypass-00eb124d
event_id: brief-2026-11-08-ibm-api-connect-auth-bypass-00eb124d
revision: 1
activity_at: "2026-11-08T02:55:44Z"
title: 'IBM API Connect: Missing authentication for critical function (CVE-2026-17324)'
slug: 2026-11-ibm-api-connect-auth-bypass-00eb124d
description: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to access sensitive configuration data and perform unauthorized actions due to missing authentication for a critical function.
date: "2026-11-08T02:55:44Z"
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
  - id: CVE-2026-17324
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17324
---

IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to access sensitive configuration data and perform unauthorized actions due to missing authentication for a critical function.
