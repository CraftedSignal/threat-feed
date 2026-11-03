---
brief_id: brief-2026-11-03-via-linux-command-injection
event_id: brief-2026-11-03-via-linux-command-injection
revision: 1
activity_at: "2026-11-03T22:21:07Z"
title: 'VIA: Command injection in VIA client for Linux (CVE-2026-95725)'
slug: 2026-11-via-linux-command-injection
description: A command injection vulnerability in the VIA client for Linux allows a low-privileged local attacker to execute arbitrary commands with elevated privileges.
date: "2026-11-03T22:21:07Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:via:client_for_linux:*:*:*:*:*:*:*:*
vendors:
  - VIA
products:
  - VIA client for Linux
cves:
  - id: CVE-2026-95725
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95725
---

CVE-2026-95725 is a command injection vulnerability in the VIA client for Linux. Successful exploitation could allow a low-privileged local attacker to execute arbitrary commands with elevated privileges on the affected system.
