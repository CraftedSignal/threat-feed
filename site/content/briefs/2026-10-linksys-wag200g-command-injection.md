---
brief_id: brief-2026-10-28-linksys-wag200g-command-injection
event_id: brief-2026-10-28-linksys-wag200g-command-injection
revision: 1
activity_at: "2026-10-28T06:25:53Z"
title: 'Linksys WAG200G: OS command injection via setup.cgi (CVE-2013-20007)'
slug: 2026-10-linksys-wag200g-command-injection
description: Linksys WAG200G firmware versions through 1.01.06 contain an OS command injection vulnerability in the timer_interval parameter that allows authenticated attackers to execute arbitrary system commands via crafted POST requests.
date: "2026-10-28T06:25:53Z"
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
  - cpe:2.3:a:linksys:wag200g:*:*:*:*:*:*:*:*
vendors:
  - Linksys
products:
  - WAG200G (through 1.01.06)
cves:
  - id: CVE-2013-20007
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2013-20007
---

Linksys WAG200G routers running firmware versions through 1.01.06 are vulnerable to OS command injection. Authenticated attackers can inject backtick-delimited input into the timer_interval parameter via a POST request to setup.cgi. This allows for the execution of commands, such as starting telnetd or downloading and running a backdoor, resulting in full device control.
