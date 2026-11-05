---
brief_id: brief-2026-11-05-edimax-command-injection
event_id: brief-2026-11-05-edimax-command-injection
revision: 1
activity_at: "2026-11-05T01:18:30Z"
title: 'Edimax BR-6208AC: Command injection via /goform/mp (CVE-2026-122051)'
slug: 2026-11-edimax-command-injection
description: A flaw in the Edimax BR-6208AC version 1.32, specifically in the /goform/mp file, allows for command injection that may be launched remotely. The vendor has not responded to disclosure attempts.
date: "2026-11-05T01:18:30Z"
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
  - cpe:2.3:a:edimax:br_6208ac:*:*:*:*:*:*:*:*
vendors:
  - Edimax
products:
  - BR-6208AC (1.32)
cves:
  - id: CVE-2026-122051
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122051
---

CVE-2026-122051 is a command injection vulnerability affecting the Edimax BR-6208AC router, version 1.32. The flaw exists in the /goform/mp file. The attack can be launched remotely, and a public exploit exists. The vendor was contacted but did not respond. The CVSS v3.1 base score is 10.0.
