---
title: disler aider-mcp-server Command Injection Vulnerability (CVE-2026-7157)
slug: 2024-01-aider-mcp-command-injection
description: A command injection vulnerability (CVE-2026-7157) exists in disler aider-mcp-server, allowing remote attackers to execute arbitrary commands by manipulating the relative_editable_files argument in the aider_ai_code component's server.py.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - aider-mcp-server
vendors:
  - disler
products:
  - aider-mcp-server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7157
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7157
rules:
  - title: Detect Command Execution from Aider MCP Server
    description: Detects command execution originating from the aider-mcp-server process, potentially indicating exploitation of the command injection vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect suspicious arguments to aider-mcp-server
    description: Detects command line arguments being passed to aider-mcp-server that contain suspicious command injection syntax
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

A command injection vulnerability, identified as CVE-2026-7157, affects disler aider-mcp-server up to commit b2516fa466d0d851932da92ee6d0e66946db9efc. The vulnerability resides within the `src/aider_mcp_server/server.py` file of the `aider_ai_code` component. It stems from improper handling of the `relative_editable_files` argument, which can be manipulated by a remote attacker to inject and execute arbitrary commands on the system. Exploitation is possible remotely, and a proof-of-concept…
