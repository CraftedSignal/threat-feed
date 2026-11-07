---
brief_id: brief-2026-11-07-ibm-api-connect-auth-bypass-074a2eb3
event_id: brief-2026-11-07-ibm-api-connect-auth-bypass-074a2eb3
revision: 1
activity_at: "2026-11-07T05:51:18Z"
title: 'IBM API Connect: Unauthorized access via improper authentication (CVE-2026-17278)'
slug: 2026-11-ibm-api-connect-auth-bypass-074a2eb3
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain an improper authentication vulnerability that allows a remote attacker to impersonate a trusted party and access sensitive API catalog and runtime configuration data.
date: "2026-11-07T05:51:18Z"
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
  - id: CVE-2026-17278
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17278
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are affected by a vulnerability (CVE-2026-17278) due to improper authentication. Information supplied by the client is not sufficiently verified, which could allow a remote attacker to appear as a trusted party and gain unauthorized access to sensitive API catalog and runtime configuration data.
