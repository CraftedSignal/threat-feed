---
brief_id: brief-2026-11-07-totolink-buffer-overflow-4b90d979
event_id: brief-2026-11-07-totolink-buffer-overflow-4b90d979
revision: 1
activity_at: "2026-11-07T22:45:56Z"
title: 'TOTOLINK CA300-PoE: Buffer overflow in UploadCustomModule (CVE-2026-124060)'
slug: 2026-11-totolink-buffer-overflow-4b90d979
description: A buffer overflow vulnerability exists in the UploadCustomModule function of the TOTOLINK CA300-PoE (version 6.2c.884) file /cgi-bin/cstecgi.cgi. The vulnerability is remotely exploitable via the File argument.
date: "2026-11-07T22:45:56Z"
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
  - id: CVE-2026-124060
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124060
---

A buffer overflow vulnerability was detected in the TOTOLINK CA300-PoE firmware version 6.2c.884. The issue resides in the UploadCustomModule function within the /cgi-bin/cstecgi.cgi file. The vulnerability can be triggered remotely by manipulating the 'File' argument. Public exploit information is available.
