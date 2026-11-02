---
brief_id: brief-2026-11-02-linksys-e8450-rce
event_id: brief-2026-11-02-linksys-e8450-rce
revision: 1
activity_at: "2026-11-02T05:17:10Z"
title: 'Linksys E8450: Stack-based buffer overflow in portal.cgi (CVE-2026-120283)'
slug: 2026-11-linksys-e8450-rce
description: A stack-based buffer overflow vulnerability has been identified in the Linksys E8450 (firmware 1.2.00.360516) within the hidden_timezone argument of /www/cgi-bin/portal.cgi.
date: "2026-11-02T05:17:10Z"
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
  - cpe:2.3:a:linksys:e8450:*:*:*:*:*:*:*:*
vendors:
  - Linksys
products:
  - E8450 (1.2.00.360516)
cves:
  - id: CVE-2026-120283
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120283
---

A vulnerability was identified in Linksys E8450 firmware version 1.2.00.360516. The issue involves the `strcpy` function in the file `/www/cgi-bin/portal.cgi`. Manipulation of the `hidden_timezone` argument leads to a stack-based buffer overflow. The attack can be executed remotely. The vendor was contacted regarding this disclosure but did not respond.
