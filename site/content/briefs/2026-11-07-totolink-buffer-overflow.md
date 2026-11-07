---
brief_id: brief-2026-11-07-totolink-buffer-overflow
event_id: brief-2026-11-07-totolink-buffer-overflow
revision: 1
activity_at: "2026-11-07T22:45:49Z"
title: 'TOTOLINK CA300-PoE: Buffer overflow in setWiFiRepeaterConfig (CVE-2026-124058)'
slug: 2026-11-07-totolink-buffer-overflow
description: A buffer overflow vulnerability exists in the setWiFiRepeaterConfig function of the /cgi-bin/cstecgi.cgi file in TOTOLINK CA300-PoE 6.2c.884, which can be triggered remotely by manipulating the ApCliKeyStr argument. Public exploit code is available.
date: "2026-11-07T22:45:49Z"
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
  - cpe:2.3:a:totolink:ca300_poe:*:*:*:*:*:*:*:*
vendors:
  - TOTOLINK
products:
  - CA300-PoE (6.2c.884)
cves:
  - id: CVE-2026-124058
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124058
---

A weakness has been identified in TOTOLINK CA300-PoE version 6.2c.884. The function setWiFiRepeaterConfig within /cgi-bin/cstecgi.cgi is affected. Manipulating the ApCliKeyStr argument can lead to a buffer overflow. The attack can be launched remotely, and the exploit has been made available to the public.
