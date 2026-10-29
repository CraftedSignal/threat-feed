---
brief_id: brief-2026-10-29-open-rce
event_id: brief-2026-10-29-open-rce
revision: 2
activity_at: "2026-10-29T18:44:03Z"
revision_history:
  - revision: 2
    at: "2026-10-29T18:44:03Z"
    checksum: sha256:3df8c71559774dc6ce458254ee614028778de2da1614484fd21a67d721592d91
    summary: OS windows; OS wsl
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/opencode-mcp-oauth-rce-windows
title: 'open: OS command injection vulnerability (CVE-2026-119025)'
slug: 2026-10-open-rce
description: The 'open' package (versions 7.2.0 before 11.0.0) contains an OS command injection vulnerability that allows attackers to execute PowerShell code by supplying crafted URLs on Windows and WSL.
date: "2026-10-29T15:36:59Z"
lastmod: "2026-10-29T18:42:04Z"
type: advisory
claim_state: <nil>
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
vendors:
  - sindresorhus
  - OpenCode
  - Model Context Protocol
products:
  - open (>= 7.2.0, < 11.0.0)
  - open (7.2.0 <= version < 11.0.0)
affected_os:
  - Windows
  - WSL
cves:
  - id: CVE-2026-119025
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119025
  - https://pwn.watch/i/opencode-mcp-oauth-rce-windows
  - https://www.cve.org/CVERecord?id=CVE-2026-119025
  - https://www.vulncheck.com/advisories/open-7.2.0-before-11.0.0-os-command-injection-via-powershell-on-windows
  - https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-q978-78c7-phqw
  - https://github.com/sindresorhus/open/releases/tag/v11.0.0
  - https://x.com/Pillar_sec/status/2112166888985722937
updates:
  - at: "2026-10-29T18:42:04Z"
    level: L1
    summary: OS windows; OS wsl
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/opencode-mcp-oauth-rce-windows
---

The 'open' package, versions 7.2.0 before 11.0.0, is vulnerable to OS command injection. Attackers can embed $(...) subexpressions in URLs, such as OAuth authorization_endpoint values from malicious MCP servers, which execute when index.js passes them unescaped to powershell -EncodedCommand. This affects Windows and WSL environments.
