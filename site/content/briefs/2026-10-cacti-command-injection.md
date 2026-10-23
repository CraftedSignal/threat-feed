---
brief_id: brief-2026-10-23-cacti-command-injection
event_id: brief-2026-10-23-cacti-command-injection
revision: 1
activity_at: "2026-10-23T15:43:15Z"
title: 'Cacti: Input validation bypass in command blocklist (CVE-2026-39902)'
slug: 2026-10-cacti-command-injection
description: Cacti versions prior to 1.2.31 contain an input validation bypass in the command blocklist, allowing an authenticated administrator to pass restricted characters.
date: "2026-10-23T15:43:15Z"
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
products:
  - Cacti (< 1.2.31)
cves:
  - id: CVE-2026-39902
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39902
---

Cacti, an open source performance and fault management framework, contains an input validation bypass in versions prior to 1.2.31. The blocklist omitted single-quotes, double-quotes, redirect operators, subshell parentheses, and braces. An authenticated administrator could save an input_string containing single-quotes, redirect operators, or subshell parentheses, and pass the security check. This issue has been patched in version 1.2.31.
