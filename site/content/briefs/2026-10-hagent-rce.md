---
brief_id: brief-2026-10-27-hagent-rce
event_id: brief-2026-10-27-hagent-rce
revision: 1
activity_at: "2026-10-27T15:50:50Z"
title: 'hagent: OS command injection in hagent_arduino and hagent_esp32 (CVE-2026-117573)'
slug: 2026-10-hagent-rce
description: hagent through commit 761eec6 is vulnerable to OS command injection via the args parameter in hagent_arduino and hagent_esp32 tools.
date: "2026-10-27T15:50:50Z"
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
  - hagent (<= 761eec6)
cves:
  - id: CVE-2026-117573
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117573
---

hagent through commit 761eec6 contains an OS command injection vulnerability. MCP clients or prompt-injected agents can supply crafted arguments to the 'args' parameter of 'hagent_arduino' and 'hagent_esp32' tools. These arguments are interpolated into 'arduino-cli' and 'idf.py' commands and executed via 'subprocess.run(shell=True)', allowing the execution of shell commands as the MCP server user.
