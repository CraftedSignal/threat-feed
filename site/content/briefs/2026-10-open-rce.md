---
brief_id: brief-2026-10-29-open-rce
event_id: brief-2026-10-29-open-rce
revision: 1
activity_at: "2026-10-29T15:36:59Z"
title: 'open: OS command injection vulnerability (CVE-2026-119025)'
slug: 2026-10-open-rce
description: The 'open' package (versions 7.2.0 before 11.0.0) contains an OS command injection vulnerability that allows attackers to execute PowerShell code by supplying crafted URLs on Windows and WSL.
date: "2026-10-29T15:36:59Z"
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
  - open (>= 7.2.0, < 11.0.0)
cves:
  - id: CVE-2026-119025
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119025
---

The 'open' package, versions 7.2.0 before 11.0.0, is vulnerable to OS command injection. Attackers can embed $(...) subexpressions in URLs, such as OAuth authorization_endpoint values from malicious MCP servers, which execute when index.js passes them unescaped to powershell -EncodedCommand. This affects Windows and WSL environments.
