---
brief_id: brief-2026-11-07-ibm-api-connect-rce-77cf3018
event_id: brief-2026-11-07-ibm-api-connect-rce-77cf3018
revision: 1
activity_at: "2026-11-07T05:55:25Z"
title: 'IBM API Connect: Remote code execution (CVE-2026-17359)'
slug: 2026-11-ibm-api-connect-rce-77cf3018
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to remote code execution. A remote authenticated attacker can influence product-generated code via user-supplied values, leading to arbitrary code execution.
date: "2026-11-07T05:55:25Z"
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
  - API Connect (10.0.8.0 through 10.0.8.12)
  - API Connect (12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-17359
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17359
---

CVE-2026-17359 affects IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2. The vulnerability allows a remote authenticated attacker to execute arbitrary code due to improper control of the generation of code, where a user-supplied value can influence the generated code.

## Impact
Successful exploitation allows for arbitrary code execution.
