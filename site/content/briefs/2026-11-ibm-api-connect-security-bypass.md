---
brief_id: brief-2026-11-08-ibm-api-connect-security-bypass
event_id: brief-2026-11-08-ibm-api-connect-security-bypass
revision: 1
activity_at: "2026-11-08T06:56:15Z"
title: 'IBM API Connect: Security restriction bypass via improper certificate validation (CVE-2026-17332)'
slug: 2026-11-ibm-api-connect-security-bypass
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a vulnerability that allows a remote attacker to bypass security restrictions through improper certificate validation.
date: "2026-11-08T06:56:15Z"
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
  - id: CVE-2026-17332
    cvss: 8.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln.detail/CVE-2026-17332
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17332
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to a security restriction bypass caused by improper certificate validation. A remote attacker could exploit this vulnerability to bypass security restrictions.
