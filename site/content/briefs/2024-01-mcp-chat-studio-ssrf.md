---
title: JoeCastrom mcp-chat-studio Server-Side Request Forgery Vulnerability
slug: 2024-01-mcp-chat-studio-ssrf
description: A server-side request forgery vulnerability exists in JoeCastrom mcp-chat-studio up to version 1.5.0 in the LLM Models API component, allowing remote attackers to manipulate the req.query.base_url argument and potentially conduct further attacks.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-7147
  - ssrf
  - mcp-chat-studio
vendors:
  - JoeCastrom
products:
  - mcp-chat-studio
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-7147
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7147
rules:
  - title: Detect mcp-chat-studio SSRF Attempt via Base URL Manipulation
    description: Detects potential SSRF attempts in mcp-chat-studio by monitoring requests to /routes/llm.js with suspicious URLs in the base_url parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect mcp-chat-studio SSRF Attempt to Internal IPs
    description: Detects potential SSRF attempts in mcp-chat-studio by monitoring requests to /routes/llm.js with internal IPs in the base_url parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability has been identified in JoeCastrom's mcp-chat-studio, affecting versions up to 1.5.0. The vulnerability resides within the LLM Models API, specifically in the `server/routes/llm.js` file. An attacker can remotely exploit this flaw by manipulating the `req.query.base_url` argument. This allows the attacker to make arbitrary HTTP requests from the server, potentially leading to information disclosure, internal service access, or other malicious…
