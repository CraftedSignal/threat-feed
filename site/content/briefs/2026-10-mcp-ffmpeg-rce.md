---
brief_id: brief-2026-10-27-mcp-ffmpeg-rce
event_id: brief-2026-10-27-mcp-ffmpeg-rce
revision: 1
activity_at: "2026-10-27T15:50:34Z"
title: 'mcp-ffmpeg: OS command injection via shell metacharacters (CVE-2026-117568)'
slug: 2026-10-mcp-ffmpeg-rce
description: The mcp-ffmpeg package through 1.0.5 contains an OS command injection vulnerability in the resize-video, extract-audio, and get-video-info tools.
date: "2026-10-27T15:50:34Z"
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
  - mcp-ffmpeg (<= 1.0.5)
cves:
  - id: CVE-2026-117568
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117568
---

mcp-ffmpeg through 1.0.5 contains an OS command injection vulnerability. Attackers can supply crafted videoPath or outputDir values to the resize-video, extract-audio, and get-video-info tools. By embedding $(), backticks, or a closing double quote in an existing file or directory name, an attacker can break out of the child_process.exec command string to execute commands as the MCP server user.

## Impact
Successful exploitation allows the execution of commands as the MCP server user.
