---
brief_id: brief-2026-11-01-wavlink-rce
event_id: brief-2026-11-01-wavlink-rce
revision: 1
activity_at: "2026-11-01T04:44:47Z"
title: 'WAVLINK WL-WN579A3-A: Remote OS command injection (CVE-2026-120195)'
slug: 2026-11-wavlink-rce
description: A remote OS command injection vulnerability exists in the Initial Setup Wizard of WAVLINK WL-WN579A3-A firmware version 2026-03-10-94f93d4.
date: "2026-11-01T04:44:47Z"
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
  - cpe:2.3:a:wavlink:wl_wn579a3_a:*:*:*:*:*:*:*:*
vendors:
  - WAVLINK
products:
  - WL-WN579A3-A (2026-03-10-94f93d4)
cves:
  - id: CVE-2026-120195
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120195
---

A security vulnerability has been detected in WAVLINK WL-WN579A3-A firmware version 2026-03-10-94f93d4. The vulnerability is located in the `set_wzdgwMesh` function within `/cgi-bin/adm.cgi` of the Initial Setup Wizard. Manipulation of the `wlan_ssid` argument leads to OS command injection. This vulnerability can be exploited remotely. Public disclosure of the exploit has occurred. The vendor was contacted early regarding this disclosure.

## Severity
CVSS v3.1 Base Score: 10.0
