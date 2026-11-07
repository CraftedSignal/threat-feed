---
brief_id: brief-2026-11-07-ibm-aspera-faspex-auth-bypass
event_id: brief-2026-11-07-ibm-aspera-faspex-auth-bypass
revision: 1
activity_at: "2026-11-07T05:48:49Z"
title: 'IBM Aspera Faspex: Authorization bypass and privilege escalation (CVE-2026-123218)'
slug: 2026-11-ibm-aspera-faspex-auth-bypass
description: IBM Aspera Faspex versions 5.0.0 through 5.0.19 could allow an authorized user to craft a specific message to bypass user authorization and gain full administrative privileges.
date: "2026-11-07T05:48:49Z"
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
  - cpe:2.3:a:ibm:aspera_faspex:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Aspera Faspex (5.0.0 through 5.0.19)
cves:
  - id: CVE-2026-123218
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123218
---

IBM Aspera Faspex versions 5.0.0 through 5.0.19 are vulnerable to an authorization bypass. An authorized user can craft a specific message to gain full administrative privileges. The vulnerability has a CVSS v3.1 Base Score of 9.8.
