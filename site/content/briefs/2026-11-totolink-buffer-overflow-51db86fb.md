---
brief_id: brief-2026-11-07-totolink-buffer-overflow-51db86fb
event_id: brief-2026-11-07-totolink-buffer-overflow-51db86fb
revision: 1
activity_at: "2026-11-07T16:54:46Z"
title: 'TOTOLINK CA300-PoE: Buffer overflow vulnerability in setWanConfig (CVE-2026-123960)'
slug: 2026-11-totolink-buffer-overflow-51db86fb
description: A buffer overflow vulnerability exists in the setWanConfig function of the TOTOLINK CA300-PoE 6.2c.884 firmware, which can be triggered remotely.
date: "2026-11-07T16:54:46Z"
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
  - TOTOLINK CA300-PoE 6.2c.884
cves:
  - id: CVE-2026-123960
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123960
---

A weakness has been identified in TOTOLINK CA300-PoE 6.2c.884 within the setWanConfig function of /cgi-bin/cstecgi.cgi. Manipulation of the pppoeUser, priDns, or secDns arguments can lead to a buffer overflow. This attack can be launched remotely, and public exploit code is available.
