---
title: Windows-MCP Unauthenticated PowerShell Control via HTTP Transports
slug: 2026-05-windows-mcp-rce
description: Windows-MCP versions prior to 0.7.5 are vulnerable to unauthenticated PowerShell control via HTTP transports due to wildcard CORS and missing authentication, allowing a remote attacker to execute arbitrary PowerShell commands as the user running Windows-MCP.
date: "2026-05-21T16:47:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - windows-mcp
  - CORS
products:
  - windows-mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-vrxg-gm77-7q5g
rules:
  - title: Detect Windows-MCP PowerShell Execution via HTTP
    description: Detects suspicious PowerShell execution via the Windows-MCP HTTP endpoint. This detects calls to the 'tools/call' method with the 'PowerShell' tool.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
  - title: Detect Windows-MCP Wildcard CORS Configuration
    description: Detects HTTP OPTIONS requests to the Windows-MCP endpoint that return a wildcard Access-Control-Allow-Origin header, indicating a vulnerable CORS configuration.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
---

Windows-MCP versions prior to 0.7.5 are vulnerable to a critical security flaw in the SSE and Streamable HTTP transport modes. This vulnerability exposes the MCP control plane without authentication and enables wildcard CORS handling, effectively allowing unauthenticated remote attackers to execute arbitrary PowerShell commands. The `PowerShell` tool, registered within Windows-MCP, executes caller-controlled commands as the Windows user running the application. This vulnerability arises from the composition of two design flaws: the lack of authentication in the FastMCP instance and the blanket wildcard CORS policy, which permits cross-origin browsers and non-browser HTTP clients to access the MCP control plane. This combination allows attackers to bypass typical security measures, leading to arbitrary code execution on the affected system.

## Attack Chain

1. Attacker sends an HTTP OPTIONS request to the `/mcp` endpoint with a crafted `Origin` header. The server responds with wildcard CORS headers, including `access-control-allow-origin: *`.
2. Attacker sends an HTTP POST request to the `/mcp` endpoint to initialize an MCP session using the `initialize` method with a specified protocol version and client information.
3. The server creates an MCP session and returns a session ID to the attacker in the `mcp-session-id` header.
4. Attacker sends an HTTP POST request to the `/mcp` endpoint, including the previously obtained `Mcp-Session-Id` in the header.
5. The attacker calls the `tools/call` method to invoke the `PowerShell` tool.
6. The attacker includes arguments in the `tools/call` request to execute a specified PowerShell command, such as `calc.exe`.
7. The Windows-MCP application executes the attacker-supplied PowerShell command using `PowerShell -EncodedCommand`.
8. The attacker achieves arbitrary code execution on the target system as the user running Windows-MCP.

## Impact

Successful exploitation allows remote attackers to execute arbitrary PowerShell commands as the user running Windows-MCP. While Chrome/Edge may block or prompt for public-site-to-localhost requests due to Local Network Access / Private Network Access behavior, the exposure still applies to same-origin/private-origin contexts, browsers or apps without this enforcement, user-approved local-network prompts, browser extensions, and non-browser HTTP clients. This can lead to complete system compromise, data exfiltration, and further malicious activities.

## Recommendation

*   Upgrade to Windows-MCP version 0.7.5 or later to patch the vulnerability.
*   Implement authentication for HTTP transports to prevent unauthenticated access to the MCP control plane.
*   Remove wildcard CORS from MCP control endpoints and restrict allowed origins to explicit trusted clients.
*   Enable and propagate transport security settings such as host validation.
*   Monitor web server logs for HTTP OPTIONS requests with suspicious `Origin` headers and subsequent requests to the `/mcp` endpoint using the `webserver` log source and deploy the Sigma rules in this brief to detect and alert on potential exploitation attempts.
