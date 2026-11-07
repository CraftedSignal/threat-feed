---
brief_id: brief-2026-11-07-ibm-api-connect-rce-dd61e43a
event_id: brief-2026-11-07-ibm-api-connect-rce-dd61e43a
revision: 1
activity_at: "2026-11-07T05:56:14Z"
title: 'IBM API Connect: Remote command execution (CVE-2026-17402)'
slug: 2026-11-ibm-api-connect-rce-dd61e43a
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain an OS command injection vulnerability that allows a remote authenticated attacker to execute arbitrary commands.
date: "2026-11-07T05:56:14Z"
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
  - id: CVE-2026-17402
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17402
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to OS command injection. This issue occurs because user-supplied input is not properly neutralized before being passed to the underlying operating system, which could allow commands to run on the host.
