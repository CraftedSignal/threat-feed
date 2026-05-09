---
title: '@profullstack/mcp-server OS Command Injection Vulnerability'
slug: 2026-05-profullstack-rce
description: The @profullstack/mcp-server is vulnerable to OS Command Injection in the domain_lookup module, allowing unauthenticated remote attackers to execute arbitrary OS commands as the server process by injecting shell metacharacters into the domains/keywords parameters via the POST /domain-lookup/check and /domain-lookup/bulk endpoints.
date: "2026-05-09T00:42:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - web-application
vendors:
  - profullstack
products:
  - '@profullstack/mcp-server (<= 1.4.12)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-v6wj-c83f-v46x
rules:
  - title: Detect profullstack/mcp-server Command Injection via domain-lookup/check
    description: Detects OS Command Injection in profullstack/mcp-server via the /domain-lookup/check endpoint by identifying shell metacharacters in the domains parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect profullstack/mcp-server Command Injection via domain-lookup/bulk
    description: Detects OS Command Injection in profullstack/mcp-server via the /domain-lookup/bulk endpoint by identifying shell metacharacters in the keywords parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

The `@profullstack/mcp-server` package is vulnerable to OS Command Injection within the `domain_lookup` module. Specifically, the application fails to sanitize user-provided input passed via the `domains` and `keywords` parameters to the `/domain-lookup/check` and `/domain-lookup/bulk` endpoints. This unsanitized input is then concatenated into a shell command string and executed using `execAsync()`. The server binds to `0.0.0.0` without global authentication middleware. This vulnerability, identified as CWE-78, allows unauthenticated remote attackers to inject arbitrary OS commands, potentially leading to complete system compromise. Version 1.4.12 and earlier are affected.

## Attack Chain

1.  An attacker sends a POST request to `/domain-lookup/check` or `/domain-lookup/bulk` with a crafted JSON payload.
2.  The JSON payload contains a `domains` or `keywords` array, with malicious commands injected using shell metacharacters (e.g., `;`, `|`, `$()`).
3.  The `buildTldxCommand()` function in `mcp_modules/domain_lookup/src/service.js` concatenates the attacker-controlled input directly into a command string without sanitization.
4.  The resulting command string is passed to the `execAsync()` function.
5.  `execAsync()` executes the command using `/bin/sh`, interpreting the injected shell metacharacters.
6.  Arbitrary OS commands are executed with the privileges of the server process.
7.  The attacker can then perform actions such as reading sensitive files, creating new files, or establishing outbound network connections.
8.  Successful exploitation results in unauthenticated remote code execution, potentially leading to full system compromise.

## Impact

Successful exploitation of this vulnerability allows for unauthenticated remote code execution with the privileges of the server process. This could lead to full read/write access to any file the server process can access, potentially sensitive information disclosure, credential theft, persistence, and lateral movement within the network. The CVSS 3.1 score is 9.8 (Critical). This vulnerability is easily reproducible with a single unauthenticated HTTP POST request to either of the documented endpoints.

## Recommendation

*   Upgrade to a patched version of `@profullstack/mcp-server` that addresses the command injection vulnerability.
*   Implement input validation on the `domains` and `keywords` parameters to reject any input containing shell metacharacters.
*   Use `child_process.execFile` or `spawn('tldx', [keyword1, keyword2, ...])` instead of `execAsync(command)` to avoid shell interpretation.
*   Deploy the Sigma rules provided in this brief to detect exploitation attempts targeting the affected endpoints and parameters.
*   Implement global authentication middleware to prevent anonymous access to HTTP-exposed modules.
*   Modify the server to bind to `127.0.0.1` by default to reduce the attack surface and require explicit opt-in for non-loopback bindings.
