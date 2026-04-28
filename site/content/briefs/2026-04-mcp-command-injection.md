---
title: dvladimirov MCP Git Search API Command Injection Vulnerability
slug: 2026-04-mcp-command-injection
description: A command injection vulnerability (CVE-2026-7211) exists in the GitSearchRequest function of dvladimirov MCP up to version 0.1.0, allowing a remote attacker to execute arbitrary commands by manipulating the repo_url or pattern argument.
date: "2026-04-28T01:16:02Z"
severities:
  - high
exploited: true
tags:
  - command-injection
  - vulnerability
  - git-search-api
vendors:
  - dvladimirov
products:
  - MCP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7211
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7211
rules:
  - title: Detect MCP Git Search API Command Injection Attempt
    description: Detects potential command injection attempts against the dvladimirov MCP Git Search API by identifying shell metacharacters in the repo_url or pattern parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect MCP Git Search API Access
    description: Detects access to the dvladimirov MCP Git Search API.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A command injection vulnerability has been identified in dvladimirov MCP (Monitoring and Configuration Platform) up to version 0.1.0. This vulnerability resides within the GitSearchRequest function located in the `mcp_server.py` file, specifically affecting the Git Search API component. Successful exploitation allows a remote attacker to inject and execute arbitrary commands on the underlying system. The vulnerability stems from insufficient sanitization of user-supplied input to the `repo_url`…
