---
title: Network-AI Unauthenticated Cross-Origin MCP Tool Invocation via Empty Default Secret (CVE-2026-46701)
slug: 2026-05-network-ai-mcp-tool-invocation
description: Network-AI is vulnerable to an unauthenticated cross-origin attack due to an empty default secret and permissive CORS configuration, allowing an attacker to lure a user to a malicious web page and invoke MCP tools like config_set, agent_spawn, and blackboard_write against a default-configured localhost server.
date: "2026-05-21T22:41:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - cve-2026-46701
  - network
  - cross-origin
  - authentication bypass
vendors:
  - Jovancoding
products:
  - Network-AI (<= 5.4.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-j3vx-cx2r-pvg8
  - CVE-2026-46701
rules:
  - title: Detect Network-AI MCP Tool Invocation Without Authorization
    description: Detects CVE-2026-46701 exploitation — HTTP POST requests to the /mcp endpoint without an Authorization header, indicating potential unauthorized MCP tool invocation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1555.003
    data_sources:
      - webserver
  - title: Detect Network-AI MCP CORS Preflight with Wildcard Origin
    description: Detects an OPTIONS request to the /mcp endpoint that results in Access-Control-Allow-Origin being set to '*', indicating a permissive CORS configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

Network-AI v5.4.4 is vulnerable to an unauthenticated cross-origin MCP tool invocation due to an empty default secret and permissive CORS settings. The MCP SSE server defaults to an empty secret, causing the `_isAuthorized` function to unconditionally return `true`. Simultaneously, `_handleRequest` sets `Access-Control-Allow-Origin: *` on every response, allowing cross-origin browser requests. An attacker can lure a user to a malicious web page and invoke all 22 exposed MCP tools, including `config_set`, `agent_spawn`, and `blackboard_write`, against a default-configured localhost server. This vulnerability is tracked as CVE-2026-46701.

## Attack Chain

1. An attacker hosts a malicious web page designed to interact with the Network-AI MCP server.
2. A user with a default-configured Network-AI MCP server running locally visits the malicious web page.
3. The malicious web page sends an HTTP OPTIONS request to the `/mcp` endpoint to check CORS preflight. The server responds with `Access-Control-Allow-Origin: *`.
4. The malicious web page sends an HTTP POST request to the `/mcp` endpoint with a JSON-RPC payload targeting a MCP tool (e.g., `config_set`). No `Authorization` header is included.
5. The server's `_isAuthorized` function evaluates to `true` because the secret is empty.
6. The server's `_handleRequest` function sets `Access-Control-Allow-Origin: *` on the response.
7. The server's `_bridge.handleRPC` function executes the requested MCP tool (e.g., `config_set` to modify configuration).
8. The malicious web page receives the response and can read the result due to the permissive CORS setting, confirming successful execution of the MCP tool.

## Impact

Any web page visited by a user who has the Network-AI MCP server running locally on the default port (3001) with no configured secret can silently invoke all 22 MCP tools without credentials. This allows for arbitrary orchestrator configuration mutation (`config_set`), spawning arbitrary agents (`agent_spawn`), corrupting shared agent state (`blackboard_write` / `blackboard_delete`), and tampering with token management (`token_create` / `token_revoke`). The integrity impact is high because core orchestrator state can be overwritten.

## Recommendation

*   Apply the vendor's suggested remediation by requiring a non-empty secret at startup (see remediation #1 in the overview) to prevent unauthorized access.
*   Implement the vendor's suggested fix by restricting CORS to localhost origins only (see remediation #2 in the overview) to prevent cross-origin requests.
*   Deploy the Sigma rule "Detect Network-AI MCP Tool Invocation Without Authorization" to identify attempts to exploit this vulnerability by monitoring POST requests to the `/mcp` endpoint without an Authorization header.
*   Upgrade to a patched version of Network-AI that addresses CVE-2026-46701.
