---
brief_id: brief-2026-11-07-totolink-buffer-overflow-ef78ab51
event_id: brief-2026-11-07-totolink-buffer-overflow-ef78ab51
revision: 1
activity_at: "2026-11-07T09:58:16Z"
title: 'TOTOLINK CA300-PoE: Buffer overflow vulnerability (CVE-2026-123958)'
slug: 2026-11-totolink-buffer-overflow-ef78ab51
description: A buffer overflow vulnerability was identified in the setLanConfig function of TOTOLINK CA300-PoE 6.2c.884.
date: "2026-11-07T09:58:16Z"
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
  - id: CVE-2026-123958
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123958
---

A buffer overflow vulnerability (CVE-2026-123958) was identified in the setLanConfig function of the /cgi-bin/cstecgi.cgi file in TOTOLINK CA300-PoE version 6.2c.884. Manipulation of the lanDns, lanSecDns, or langType arguments leads to a buffer overflow. The attack can be launched remotely, and the exploit is publicly available.
