---
brief_id: brief-2026-10-22-totolink-ex200-rce
event_id: brief-2026-10-22-totolink-ex200-rce
revision: 1
activity_at: "2026-10-22T01:51:16Z"
title: 'TOTOLINK EX200: Stack-based buffer overflow in setStaticDhcpConfig (CVE-2026-114382)'
slug: 2026-10-totolink-ex200-rce
description: A security flaw in TOTOLINK EX200 firmware 5.2.3c.7200 allows for remote stack-based buffer overflow via the Comment argument in the setStaticDhcpConfig function.
date: "2026-10-22T01:51:16Z"
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
products:
  - TOTOLINK EX200 (5.2.3c.7200)
cves:
  - id: CVE-2026-114382
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114382
---

A security flaw has been identified in TOTOLINK EX200 version 5.2.3c.7200. The vulnerability exists within the 'setStaticDhcpConfig' function of the '/cgi-bin/cstecgi.cgi' file in the 'lan.so' component. Manipulating the 'Comment' argument triggers a stack-based buffer overflow. The attack can be launched remotely, and a public exploit is available.
