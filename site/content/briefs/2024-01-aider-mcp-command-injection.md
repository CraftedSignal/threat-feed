---
title: disler aider-mcp-server Command Injection Vulnerability (CVE-2026-7157)
slug: 2024-01-aider-mcp-command-injection
description: A command injection vulnerability (CVE-2026-7157) exists in disler aider-mcp-server, allowing remote attackers to execute arbitrary commands by manipulating the relative_editable_files argument in the aider_ai_code component's server.py.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
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
    epss: 0.01039
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

A command injection vulnerability, identified as CVE-2026-7157, affects disler aider-mcp-server up to commit b2516fa466d0d851932da92ee6d0e66946db9efc. The vulnerability resides within the `src/aider_mcp_server/server.py` file of the `aider_ai_code` component. It stems from improper handling of the `relative_editable_files` argument, which can be manipulated by a remote attacker to inject and execute arbitrary commands on the system. Exploitation is possible remotely, and a proof-of-concept exploit has been published, increasing the risk of widespread attacks. The project follows a rolling release model, so specific patched versions are not available, making mitigation challenging.

## Attack Chain

1.  Attacker identifies a vulnerable instance of `aider-mcp-server` running a version up to commit `b2516fa466d0d851932da92ee6d0e66946db9efc`.
2.  Attacker crafts a malicious request targeting the vulnerable functionality in `src/aider_mcp_server/server.py`.
3.  The crafted request includes a payload within the `relative_editable_files` argument designed to inject shell commands.
4.  The `aider-mcp-server` processes the request and improperly sanitizes the `relative_editable_files` argument.
5.  The unsanitized argument is passed to a function that executes shell commands.
6.  The injected commands are executed on the server with the privileges of the `aider-mcp-server` process.
7.  Attacker gains arbitrary code execution on the server.
8.  The attacker can then perform actions such as installing malware, accessing sensitive data, or pivoting to other systems.

## Impact

Successful exploitation of this command injection vulnerability allows a remote attacker to execute arbitrary commands on the affected server. This can lead to complete system compromise, including data theft, malware installation, and denial of service. Given that an exploit is publicly available, the risk of exploitation is significantly elevated. The lack of versioned releases makes patching and mitigation more complex, potentially affecting any instance running a version prior to a fix being implemented.

## Recommendation

*   Inspect `aider-mcp-server` logs for suspicious activity related to requests targeting `src/aider_mcp_server/server.py` and the handling of `relative_editable_files` to detect potential exploitation attempts.
*   Deploy the provided Sigma rule to detect command execution originating from the `aider-mcp-server` process.
*   Monitor network connections originating from the `aider-mcp-server` for unexpected outbound activity.
