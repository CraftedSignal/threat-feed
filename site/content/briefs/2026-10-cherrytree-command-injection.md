---
brief_id: brief-2026-10-28-cherrytree-command-injection
event_id: brief-2026-10-28-cherrytree-command-injection
revision: 1
activity_at: "2026-10-28T22:48:28Z"
title: 'CherryTree: OS command injection via CtActions (CVE-2026-118692)'
slug: 2026-10-cherrytree-command-injection
description: CherryTree through 1.7.2 contains an OS command injection vulnerability in CtActions::link_clicked, allowing command execution via shell metacharacters in web link URLs when the non-default Custom Web Link Clicked Action is enabled.
date: "2026-10-28T22:48:28Z"
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
  - CherryTree (through 1.7.2)
cves:
  - id: CVE-2026-118692
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118692
---

CherryTree versions through 1.7.2 contain an OS command injection vulnerability in the `CtActions::link_clicked` function. This vulnerability occurs when the non-default "Custom Web Link Clicked Action" option is enabled. Attackers can embed shell metacharacters such as `$(...)`, backticks, or semicolons in web link URLs. When a user clicks such a link, the application passes the unquoted input to `std::system`, resulting in the execution of commands.
