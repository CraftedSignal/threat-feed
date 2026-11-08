---
brief_id: brief-2026-11-08-ibm-webmethods-auth-bypass
event_id: brief-2026-11-08-ibm-webmethods-auth-bypass
revision: 1
activity_at: "2026-11-08T19:35:15Z"
title: 'IBM webMethods Integration Server: Authentication bypass (CVE-2026-117545)'
slug: 2026-11-ibm-webmethods-auth-bypass
description: IBM webMethods Integration Server 12.1 contains an improper authentication vulnerability that permits a remote authenticated attacker to bypass security restrictions.
date: "2026-11-08T19:35:15Z"
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
  - cpe:2.3:a:ibm:webmethods_integration_server:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - webMethods Integration Server (12.1)
cves:
  - id: CVE-2026-117545
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117545
---

IBM webMethods Integration Server 12.1 is vulnerable to an improper authentication flaw (CVE-2026-117545). This vulnerability could allow a remote authenticated attacker to bypass security restrictions. The issue has been assigned a CVSS v3.1 Base Score of 8.8.
