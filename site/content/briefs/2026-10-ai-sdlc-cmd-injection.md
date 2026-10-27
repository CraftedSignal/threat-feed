---
brief_id: brief-2026-10-27-ai-sdlc-cmd-injection
event_id: brief-2026-10-27-ai-sdlc-cmd-injection
revision: 1
activity_at: "2026-10-27T15:49:54Z"
title: 'ai-sdlc plugin MCP server: OS command injection (CVE-2026-117558)'
slug: 2026-10-ai-sdlc-cmd-injection
description: The ai-sdlc plugin MCP server through 0.31.2 is vulnerable to OS command injection via the repo argument, allowing execution of commands by supplying shell metacharacters.
date: "2026-10-27T15:49:54Z"
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
tags:
  - command-injection
  - vulnerability
  - mcp-server
products:
  - ai-sdlc plugin MCP server (<= 0.31.2)
cves:
  - id: CVE-2026-117558
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117558
---

The ai-sdlc plugin MCP server through version 0.31.2 contains an OS command injection vulnerability. The repo argument is not validated and is interpolated into gh issue view or gh pr view commands run via execSync(). This allows prompt-injected agents to execute commands as the MCP server user.
