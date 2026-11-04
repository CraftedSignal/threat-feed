---
brief_id: brief-2026-11-04-zip-slip-gohttpserver
event_id: brief-2026-11-04-zip-slip-gohttpserver
revision: 1
activity_at: "2026-11-04T00:24:43Z"
title: 'gohttpserver: Zip Slip arbitrary file write (CVE-2026-38600)'
slug: 2026-11-zip-slip-gohttpserver
description: A Zip Slip vulnerability in the /upload endpoint of codeskyblue gohttpserver through v1.3.0 allows attackers to write arbitrary files via uploading a crafted Zip archive.
date: "2026-11-04T00:24:43Z"
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
  - cpe:2.3:a:codeskyblue:gohttpserver:*:*:*:*:*:*:*:*
vendors:
  - codeskyblue
products:
  - gohttpserver (through v1.3.0)
cves:
  - id: CVE-2026-38600
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-38600
---

CVE-2026-38600 is a Zip Slip vulnerability in the /upload endpoint of codeskyblue gohttpserver through v1.3.0. This vulnerability allows attackers to write arbitrary files by uploading a crafted Zip archive.
