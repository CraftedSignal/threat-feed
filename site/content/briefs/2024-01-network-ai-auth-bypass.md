---
title: Network-AI Unauthenticated Access to MCP HTTP Endpoint
slug: 2024-01-network-ai-auth-bypass
description: Network-AI is vulnerable to missing authentication on the MCP HTTP endpoint, allowing unauthenticated privileged tool calls that could lead to configuration changes and agent manipulation.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cwe-306
  - authentication-bypass
  - network-ai
vendors:
  - Jovancoding
products:
  - Network-AI (<= 5.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-fj4g-2p96-q6m3
iocs:
  - type: url
    value: http://localhost:13001/tools
  - type: url
    value: http://localhost:13001/mcp
ioc_counts:
  url: 2
rules:
  - title: Detect Unauthenticated Access to Network-AI MCP Endpoint
    description: Detects unauthenticated HTTP POST requests to the /mcp endpoint, indicating potential exploitation of the missing authentication vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Network-AI Tool Enumeration
    description: Detects HTTP GET requests to the /tools endpoint, which may indicate an attacker attempting to enumerate available tools before exploiting the vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `Jovancoding/Network-AI` project is susceptible to a critical vulnerability due to missing authentication on the MCP HTTP endpoint. This flaw, present in version 5.1.2 and earlier (commit `c344f2053eb0d49395988f803bf92f2a86b2a0d0`), allows unauthenticated access to the orchestrator's management tools. The default bind address of `0.0.0.0` exacerbates the issue, enabling any party with network reachability to enumerate and invoke privileged functions. This includes reading and mutating the live orchestrator configuration, listing registered agents, creating/revoking security tokens, and adjusting global budget ceilings, posing a significant risk to the system's integrity and availability.

## Attack Chain

1. The attacker gains network access to the Network-AI instance.
2. The attacker sends an HTTP GET request to `/tools` endpoint (e.g., `http://localhost:13001/tools`) to enumerate available tools.
3. The server responds with a list of available tools including `config_get`, `config_set`, `agent_list`, etc.
4. The attacker crafts a JSON-RPC `tools/call` request to the `/mcp` endpoint (e.g., `http://localhost:13001/mcp`) without any authentication headers.
5. The attacker specifies the desired tool name (`config_get`, `config_set`, `agent_list`, etc.) and arguments within the JSON-RPC request body.
6. The server processes the request and dispatches the call to the orchestrator's tool registry without authentication.
7. The attacker can now read sensitive configuration data using `config_get` or modify the configuration using `config_set`.
8. The attacker can further enumerate agents or manipulate the system by using available tool calls like `agent_list`, `agent_spawn`, and `agent_stop`.

## Impact

Successful exploitation of this vulnerability allows an attacker to completely compromise the Network-AI orchestrator. Unauthenticated network access enables full enumeration and invocation of the orchestrator's management functionality. An attacker can change runtime configuration (e.g., `defaultTimeout`, `enableTracing`), dispatch or stop agents, mutate the shared blackboard, mint or revoke security tokens, and adjust global budget ceilings. The default `0.0.0.0` bind increases the likelihood of accidental exposure on any host with a routable interface.

## Recommendation

*   Deploy the Sigma rule "Detect Unauthenticated Access to Network-AI MCP Endpoint" to identify suspicious requests to the `/mcp` endpoint without authentication (see rule below).
*   Monitor web server logs for HTTP requests to `/tools` and `/mcp` endpoints originating from unexpected IP addresses, especially those outside the internal network.
*   Apply remediation steps suggested by the vendor, including enforcing authentication on the `/mcp` endpoint and restricting the bind address to `127.0.0.1`.
*   Use the IOCs provided in this brief to identify potential exploitation attempts by blocking access to the identified URLs and IP addresses.
