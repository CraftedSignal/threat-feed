---
brief_id: brief-2026-10-27-droidmind-command-injection
event_id: brief-2026-10-27-droidmind-command-injection
revision: 1
activity_at: "2026-10-27T15:50:01Z"
title: 'DroidMind: Command injection vulnerability (CVE-2026-117559)'
slug: 2026-10-droidmind-command-injection
description: DroidMind through 0.4.0 contains a command injection vulnerability that allows MCP clients to bypass the shell command allowlist by using $(...) or backtick substitution.
date: "2026-10-27T15:50:01Z"
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
  - cpe:2.3:a:droidmind:droidmind:*:*:*:*:*:*:*:*
vendors:
  - DroidMind
products:
  - DroidMind (<= 0.4.0)
cves:
  - id: CVE-2026-117559
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117559
---

DroidMind through 0.4.0 contains a command injection vulnerability. MCP clients can bypass the shell command allowlist by using $(...) or backtick substitution. Attackers, including prompt-injected agents, can inject commands through parameters interpolated into Device.run_shell() or unvalidated Device.list_directory() to run blocked commands such as reboot on connected Android devices.
