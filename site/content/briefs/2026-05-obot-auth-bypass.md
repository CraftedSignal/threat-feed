---
title: Obot Authorization Bypass in /mcp-connect/{id} Endpoint
slug: 2026-05-obot-auth-bypass
description: Obot version 0.21.0 has an authorization bypass vulnerability in the `/mcp-connect/{id}` endpoint allowing any authenticated user to connect to any registered MCP server, regardless of permissions, leading to unauthorized access and actions on upstream services.
date: "2026-05-13T15:36:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authorization bypass
  - privilege escalation
  - mcp
  - cloud
vendors:
  - obot-platform
products:
  - obot
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-vw82-7fv8-r6gp
rules:
  - title: Detect Obot MCP Connect Authorization Bypass
    description: Detects unauthorized access to the /mcp-connect endpoint in Obot, indicating a potential authorization bypass attempt.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Obot MCP Tool Call via POST
    description: Detects POST requests to Obot's MCP endpoints with JSON-RPC payloads indicative of tool execution, potentially exploiting authorization bypass.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

Obot version 0.21.0 is vulnerable to an authorization bypass in the `/mcp-connect/{id}` endpoint. This flaw allows any authenticated user, even those without explicit permissions, to connect to any registered MCP server. The vulnerability stems from a missing access control check on the `/mcp-connect/{mcp_id}` gateway endpoint. This means that any user possessing an MCP Server ID can connect to that server through the gateway and make tool calls, effectively circumventing intended restrictions. This critical vulnerability could enable unauthorized access to sensitive data and operations on upstream third-party services accessible via Obot's stored OAuth credentials.

## Attack Chain

1. An attacker identifies a target MCP server ID.
2. The attacker authenticates to Obot with a basic user account.
3. The attacker crafts a malicious POST request to `/mcp-connect/<mcp_server_id>`.
4. The request includes a valid Obot session cookie or API key in the `Authorization` header.
5. The request body contains a JSON-RPC payload to list available tools on the MCP server: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`.
6. The attacker observes a successful response, confirming access to the MCP server's tools, bypassing intended access controls.
7. The attacker crafts a subsequent JSON-RPC request to call a sensitive tool: `{"jsonrpc":"2.0","id":2,"method":"tools/call", "params":{"name":"<sensitive_tool>","arguments":{...}}}`.
8. The attacker executes the tool call successfully, gaining access to data and functionality normally restricted to authorized users, leveraging the MCP server's OAuth credentials.

## Impact

This vulnerability allows unauthorized users to access and manipulate sensitive data within connected MCP servers. The severity of the impact depends on the capabilities exposed by the affected MCP servers and the scope of their stored OAuth credentials. A successful exploit could lead to unauthorized data exfiltration, modification of critical systems, or other malicious activities, potentially impacting a wide range of services integrated with Obot, and could affect any number of Obot users.

## Recommendation

*   Upgrade to a patched version of Obot that addresses the authorization bypass vulnerability.
*   Monitor web server logs for POST requests to `/mcp-connect/` with unusual user agents or API keys, using the `Detect Obot MCP Connect Authorization Bypass` Sigma rule.
*   Implement strict access control policies for MCP server registrations to limit the potential blast radius of a successful exploit.
*   Review and restrict the permissions granted to Obot's stored OAuth credentials to minimize the impact of unauthorized access.
