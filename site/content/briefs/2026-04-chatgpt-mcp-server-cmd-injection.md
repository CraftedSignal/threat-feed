---
title: Toowiredd chatgpt-mcp-server OS Command Injection Vulnerability
slug: 2026-04-chatgpt-mcp-server-cmd-injection
description: Toowiredd chatgpt-mcp-server up to version 0.1.0 is vulnerable to OS command injection via the file src/services/docker.service.ts of the component MCP/HTTP, allowing for remote exploitation.
date: "2026-04-26T22:17:33Z"
severities:
  - high
tags:
  - cve-2026-7061
  - command-injection
  - webserver
vendors:
  - Toowiredd
products:
  - chatgpt-mcp-server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7061
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7061
  - https://github.com/Toowiredd/chatgpt-mcp-server/
  - https://github.com/Toowiredd/chatgpt-mcp-server/issues/8
  - https://github.com/wing3e/public_exp/issues/28
  - https://vuldb.com/submit/798613
  - https://vuldb.com/vuln/359636
  - https://vuldb.com/vuln/359636/cti
rules:
  - title: Detect Suspicious chatgpt-mcp-server Command Injection Attempts
    description: Detects potential command injection attempts targeting chatgpt-mcp-server by analyzing HTTP request URIs for suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious chatgpt-mcp-server Child Processes
    description: Detects potential exploitation of chatgpt-mcp-server by monitoring for suspicious child processes spawned by it.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Toowiredd chatgpt-mcp-server, specifically versions up to 0.1.0, contains an OS command injection vulnerability within the `src/services/docker.service.ts` file of the MCP/HTTP component. This flaw allows for remote exploitation, potentially enabling attackers to execute arbitrary commands on the underlying operating system. The vulnerability, identified as CVE-2026-7061, has a publicly available exploit, increasing the risk of exploitation. The project maintainers were notified via an issue…
