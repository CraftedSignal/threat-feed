---
brief_id: brief-2026-10-27-kali-gpt-rce
event_id: brief-2026-10-27-kali-gpt-rce
revision: 1
activity_at: "2026-10-27T15:50:42Z"
title: 'Kali-GPT: OS command injection via execute_tool() (CVE-2026-117569)'
slug: 2026-10-kali-gpt-rce
description: Kali-GPT versions through commit a608c74 are vulnerable to OS command injection in the execute_tool() function in kali_gpt/tools/mcp_server.py.
date: "2026-10-27T15:50:42Z"
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
  - Kali-GPT through commit a608c74
cves:
  - id: CVE-2026-117569
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117569
---

Kali-GPT versions through commit a608c74 contain an OS command injection vulnerability in the execute_tool() function in kali_gpt/tools/mcp_server.py. This allows MCP clients to run commands via unsanitized scanner parameters (target, ports, domain, wordlist, or url). These parameters are executed via subprocess.run with shell=True as the MCP server user.
