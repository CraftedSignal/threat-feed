---
title: Penpot MCP REPL Server Unauthenticated Remote Code Execution
slug: 2026-05-penpot-mcp-rce
description: The Penpot MCP module's ReplServer binds to all interfaces and exposes an unauthenticated /execute endpoint, allowing remote attackers to execute arbitrary code by sending a POST request with JavaScript code, leading to potential information disclosure and command execution.
date: "2026-05-19T20:00:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - unauthenticated-access
vendors:
  - Penpot
products:
  - '@penpot/mcp (< 2.15.0)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1205
    technique_name: Traffic Signaling
references:
  - https://github.com/advisories/GHSA-22qr-rp27-j9wm
rules:
  - title: Detect Penpot MCP Unauthenticated Code Execution Attempt
    description: Detects CVE-2026-45805 exploitation — attempts to execute arbitrary code via the unauthenticated /execute endpoint in Penpot MCP's ReplServer.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1205.001
    data_sources:
      - webserver
  - title: Detect Penpot MCP ReplServer Binding to All Interfaces
    description: Detects Penpot MCP ReplServer binding to all interfaces (0.0.0.0 or ::) by inspecting process command lines.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Penpot MCP (Meta Communication Protocol) module contains a vulnerability in its `ReplServer` component. This server, designed for interactive code execution, inadvertently binds to all network interfaces (0.0.0.0) on port 4403 and exposes an `/execute` endpoint without any form of authentication. This means that any system on the network can send a POST request to this endpoint with a JSON payload containing JavaScript code, which will then be executed on the Penpot MCP server. The vulnerability was reported after a similar issue was identified in `PenpotMcpServer.ts` and partially addressed. However, `ReplServer.ts` was overlooked during the fix. The issue exists in versions prior to 2.15.0.

## Attack Chain

1. The attacker identifies a Penpot MCP server running with the vulnerable `ReplServer` component.
2. The attacker determines the server's IP address and confirms the `/execute` endpoint is accessible on port 4403.
3. The attacker crafts a POST request to `http://<target-ip>:4403/execute` with a JSON payload.
4. The JSON payload contains a "code" field with malicious JavaScript code to be executed on the server.
5. The server receives the POST request and executes the JavaScript code via `PluginBridge.executePluginTask()`.
6. The executed code performs malicious actions, such as reading sensitive files (e.g., `/etc/passwd`), executing system commands (e.g., `id`), or dumping environment variables.
7. The server sends a JSON response back to the attacker with the results of the code execution.
8. The attacker leverages the exposed information or continues to execute commands to compromise the system further.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary code on the machine running the MCP module. This can lead to sensitive information disclosure, such as reading files containing credentials and API keys, as well as executing system commands with the privileges of the Penpot MCP server process. Although the MCP module isn't part of the default Docker deployment, it may be used by developers and teams for AI-assisted design work. If deployed in shared development environments or CI/CD pipelines, the exposed port is reachable from the network, increasing the risk of compromise.

## Recommendation

*   Upgrade the `@penpot/mcp` package to version 2.15.0 or later to patch CVE-2026-45805.
*   Modify the `ReplServer.ts` file to bind to localhost by adding the 'localhost' host parameter to the `listen` call on line 89, as described in the suggested fix.
*   Implement authentication for the `/execute` endpoint to prevent unauthorized access. Consider using a shared secret from an environment variable as a basic authentication mechanism.
*   Deploy the Sigma rule "Detect Penpot MCP Unauthenticated Code Execution Attempt" to detect attempts to exploit this vulnerability.
