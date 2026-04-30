---
title: VetCoders mcp-server-semgrep OS Command Injection Vulnerability
slug: 2026-05-vetcoders-command-injection
description: VetCoders mcp-server-semgrep version 1.0.0 is vulnerable to remote OS command injection due to manipulation of the ID argument in several functions of the MCP Interface component.
date: "2026-04-30T00:17:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - mcp-server-semgrep
vendors:
  - VetCoders
products:
  - mcp-server-semgrep 1.0.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7446
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7446
rules:
  - title: Detect mcp-server-semgrep Command Injection Attempt via Web Logs
    description: Detects potential command injection attempts targeting mcp-server-semgrep by monitoring web server logs for suspicious patterns in the request URI and query parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect mcp-server-semgrep Command Injection Attempt via Audit Logs
    description: Detects potential command injection attempts by monitoring application logs of mcp-server-semgrep for system commands execution
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - application
      - linux
rules_count: 2
---

A critical OS command injection vulnerability has been identified in VetCoders mcp-server-semgrep version 1.0.0. The vulnerability resides within the MCP Interface component, specifically affecting the `analyze_results`, `filter_results`, `export_results`, `compare_results`, `scan_directory`, and `create_rule` functions in the `src/index.ts` file. Successful exploitation allows for remote attackers to inject and execute arbitrary operating system commands on the affected system. The vulnerability is publicly known and actively exploitable. VetCoders has released version 1.0.1 to address this issue, with patch `141335da044e53c3f5b315e0386e01238405b771` containing the fix. Defenders should prioritize upgrading to version 1.0.1 to mitigate this risk.

## Attack Chain

1.  The attacker identifies a vulnerable instance of VetCoders mcp-server-semgrep version 1.0.0.
2.  The attacker crafts a malicious request targeting one of the vulnerable functions: `analyze_results`, `filter_results`, `export_results`, `compare_results`, `scan_directory`, or `create_rule`.
3.  The malicious request includes a manipulated `ID` argument designed to inject OS commands.
4.  The application fails to properly sanitize or validate the `ID` argument.
5.  The application executes the injected OS command using a function such as `exec`, `system`, or equivalent within the affected functions in `src/index.ts`.
6.  The injected command executes with the privileges of the mcp-server-semgrep process.
7.  The attacker gains arbitrary code execution on the server.
8.  The attacker can then perform actions such as data exfiltration, lateral movement, or denial of service.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary operating system commands on the affected server. This could lead to complete system compromise, including data theft, modification, or destruction. Depending on the server's role and the attacker's objectives, this could result in significant financial loss, reputational damage, and disruption of services. There is no information about specific victim counts or targeted sectors.

## Recommendation

*   Upgrade to VetCoders mcp-server-semgrep version 1.0.1 to remediate the vulnerability as identified in CVE-2026-7446.
*   Monitor web server logs for suspicious requests targeting the `/src/index.ts` file with unusual or potentially malicious input in the `ID` argument, using the Sigma rules provided.
*   Implement input validation and sanitization for all user-supplied input, especially the `ID` parameter, to prevent command injection attacks.
