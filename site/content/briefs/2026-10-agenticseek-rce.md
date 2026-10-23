---
brief_id: brief-2026-10-23-agenticseek-rce
event_id: brief-2026-10-23-agenticseek-rce
revision: 1
activity_at: "2026-10-23T15:42:32Z"
title: 'AgenticSeek: Remote Code Execution via Flask Debug Mode (CVE-2026-115727)'
slug: 2026-10-agenticseek-rce
description: AgenticSeek before commit 409840c contains a remote code execution vulnerability because llm_server/app.py hardcodes Flask debug mode while binding to all interfaces.
date: "2026-10-23T15:42:32Z"
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
  - AgenticSeek (< 409840c)
cves:
  - id: CVE-2026-115727
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115727
---

AgenticSeek versions before commit 409840c contain a remote code execution vulnerability. The `llm_server/app.py` file hardcodes Flask debug mode while binding to all interfaces. Attackers who reach the server port and obtain the derivable Werkzeug debugger PIN can execute Python code and operating system commands with llm_server privileges.
