---
title: OS Command Injection in token-optimizer-mcp via smart_user
slug: 2026-08-token-optimizer-mcp-rce
description: The token-optimizer-mcp package is vulnerable to OS command injection via the smart_user tool due to insecure interpolation of user-supplied input into shell commands, allowing arbitrary command execution with application privileges.
date: "2026-08-15T02:07:02Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - ooples
products:
  - token-optimizer-mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability is an OS command injection where an attacker can execute arbitrary commands via POSIX shell command substitution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-49mq-fc6q-3h46
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55157
rules:
  - title: Detects CVE-2026-55157 Exploitation - Suspicious Shell Spawning from Nodejs
    description: Detects the MCP server process spawning shell commands, which may indicate command injection exploitation of the smart_user tool.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch token-optimizer-mcp to version 5.1.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-55157 vendor patch
    - action: Deploy Sigma detection rule to identify potential shell injection attempts
      owner: Detection Engineering
      due: 24h
      evidence: Source document describes command injection path
---

The `@ooples/token-optimizer-mcp` package (versions prior to 5.1.0) contains an OS command injection vulnerability within the `smart_user` tool's `get-user-info` operation. The application insecurely interpolates the user-provided `username` argument directly into a shell command string that is subsequently executed using `execAsync()`.

The implementation uses the pattern `getent passwd "${username}" || grep "^${username}:" /etc/passwd`. Because POSIX shells evaluate command substitution syntax such as `$(...)` and backticks even when enclosed in double quotes, the application fails to sanitize malicious inputs. An attacker capable of invoking the `smart_user` tool through an MCP client can inject shell metacharacters to execute arbitrary commands with the identity and permissions of the process running the MCP server. This vulnerability, identified as CVE-2026-55157, poses a significant risk to the integrity and confidentiality of the host environment.

## Attack Chain

1. An attacker gains access to an MCP client that can interact with the token-optimizer-mcp server.
2. The attacker identifies the `smart_user` tool as a potential vector for interaction with the operating system.
3. The attacker crafts a malicious JSON-RPC request for the `tools/call` method targeting the `smart_user` tool.
4. The `username` argument is populated with an injection payload, such as `$(id > /tmp/pwned)`.
5. The MCP server receives the request and passes the malicious string into the `get-user-info` tool implementation.
6. The `execAsync()` function executes the shell command containing the attacker-controlled payload.
7. The POSIX shell parses the command substitution inside the double quotes, triggering the execution of the injected command.
8. The injected command runs with the privileges of the MCP server, potentially leading to system compromise or data exfiltration.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the user running the MCP server process. This can lead to unauthorized access to system resources, potential lateral movement, and the execution of malicious tasks such as file creation or data exfiltration. The vulnerability impacts all environments where `@ooples/token-optimizer-mcp` version 5.0.1 or earlier is deployed.

## Recommendation

1. Upgrade `@ooples/token-optimizer-mcp` to version 5.1.0 or later immediately to patch CVE-2026-55157.
2. Implement input validation and sanitization for all user-supplied arguments passed to shell execution functions.
3. Replace calls to shell-interpreting functions like `execAsync()` with safer alternatives that do not invoke a shell (e.g., using `execFile()` with distinct argument arrays).
4. Deploy the suggested Sigma rule to monitor for child processes spawned by the MCP server process.
