---
brief_id: brief-2026-10-29-dlink-dir505-backdoor
event_id: brief-2026-10-29-dlink-dir505-backdoor
revision: 1
activity_at: "2026-10-29T00:59:47Z"
title: 'D-Link DIR-505: Web management backdoor vulnerability (CVE-2026-118579)'
slug: 2026-10-dlink-dir505-backdoor
description: A weakness in the D-Link DIR-505 (version 1.10B02) Web Management CGI component allows for remote backdoor creation via argument manipulation.
date: "2026-10-29T00:59:47Z"
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
  - cpe:2.3:a:d_link:dir_505:*:*:*:*:*:*:*:*
vendors:
  - D-Link
products:
  - DIR-505 (1.10B02)
cves:
  - id: CVE-2026-118579
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118579
---

A vulnerability has been identified in the main function of /secmark1524.cgi within the Web Management CGI component of D-Link DIR-505 firmware version 1.10B02. Manipulating the accu, pass, code, hash, or cmds arguments results in a backdoor. The attack can be performed remotely, and public exploit code is available.
