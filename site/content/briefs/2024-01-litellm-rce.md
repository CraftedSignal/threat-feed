---
title: LiteLLM Authenticated Command Execution via MCP stdio Test Endpoints
slug: 2024-01-litellm-rce
description: Authenticated users with low-privilege API keys could execute arbitrary commands on the host running LiteLLM via the `/mcp-rest/test/connection` and `/mcp-rest/test/tools/list` endpoints, by submitting a server configuration including command execution parameters.
date: "2024-01-03T12:00:00Z"
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

LiteLLM versions 1.74.2 through 1.83.6 are vulnerable to authenticated command execution. Two endpoints, `POST /mcp-rest/test/connection` and `POST /mcp-rest/test/tools/list`, intended for previewing MCP server configurations, allowed any authenticated user to execute arbitrary commands on the proxy host. This was possible because the endpoints accepted a full server configuration in the request body, including the `command`, `args`, and `env` fields used by the stdio transport, without proper…
