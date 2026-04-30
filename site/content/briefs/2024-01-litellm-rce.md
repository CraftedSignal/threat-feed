---
title: LiteLLM Authenticated Command Execution via MCP stdio Test Endpoints
slug: 2024-01-litellm-rce
description: Authenticated users with low-privilege API keys could execute arbitrary commands on the host running LiteLLM via the `/mcp-rest/test/connection` and `/mcp-rest/test/tools/list` endpoints, by submitting a server configuration including command execution parameters.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - litellm
  - command-injection
vendors:
  - pip
products:
  - litellm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-v4p8-mg3p-g94g
rules:
  - title: Detect POST Requests to LiteLLM MCP Test Endpoints
    description: Detects POST requests to the /mcp-rest/test/connection or /mcp-rest/test/tools/list endpoints, potentially indicating an attempt to exploit the command execution vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Commands in LiteLLM MCP Test Requests
    description: Detects suspicious commands within the request body of POST requests to the /mcp-rest/test/connection or /mcp-rest/test/tools/list endpoints, potentially indicating command execution attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

LiteLLM versions 1.74.2 through 1.83.6 are vulnerable to authenticated command execution. Two endpoints, `POST /mcp-rest/test/connection` and `POST /mcp-rest/test/tools/list`, intended for previewing MCP server configurations, allowed any authenticated user to execute arbitrary commands on the proxy host. This was possible because the endpoints accepted a full server configuration in the request body, including the `command`, `args`, and `env` fields used by the stdio transport, without proper role checks. An attacker could exploit this vulnerability by using a low-privilege API key to send a crafted request containing malicious commands, leading to command execution with the privileges of the proxy process. The vulnerability was patched in version 1.83.7 by enforcing the `PROXY_ADMIN` role for these endpoints.

## Attack Chain

1. Attacker authenticates to the LiteLLM proxy with a valid, but low-privilege, API key.
2. Attacker crafts a malicious JSON payload containing a server configuration intended for the stdio transport. The payload includes the `command`, `args`, and `env` fields, which specify the command to be executed, its arguments, and environment variables, respectively.
3. Attacker sends a `POST` request to either the `/mcp-rest/test/connection` or `/mcp-rest/test/tools/list` endpoint, with the malicious JSON payload in the request body.
4. The LiteLLM proxy receives the request and, due to the vulnerability, attempts to connect to the supplied server configuration.
5. The proxy spawns the supplied command as a subprocess on the proxy host, using the privileges of the proxy process.
6. The attacker-supplied command executes arbitrary code on the host.
7. The attacker gains control of the proxy host with the privileges of the LiteLLM proxy.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the host running the LiteLLM proxy. Since the vulnerability can be exploited with a low-privilege API key, this significantly broadens the attack surface. Depending on the privileges of the proxy process, this could lead to full system compromise, data exfiltration, or denial of service. The lack of specific victim count or sector targeting information in the advisory suggests a broad potential impact across various deployments of LiteLLM.

## Recommendation

*   Upgrade LiteLLM to version 1.83.7 or later to remediate the vulnerability (see Patches).
*   As a temporary workaround, block `POST` requests to the `/mcp-rest/test/connection` and `/mcp-rest/test/tools/list` endpoints at your reverse proxy or API gateway (see Workarounds).
*   Monitor web server logs for `POST` requests to `/mcp-rest/test/connection` and `/mcp-rest/test/tools/list` endpoints, looking for suspicious `command`, `args`, and `env` parameters in the request body (see rules below).
