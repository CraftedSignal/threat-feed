---
title: camofox-mcp Unauthenticated HTTP MCP Endpoint
slug: 2026-05-camofox-mcp-unauth
description: camofox-mcp exposed an unauthenticated HTTP MCP endpoint, allowing remote clients to invoke browser-control tools without authentication, potentially leading to unauthorized browser automation and data access.
date: "2026-05-19T20:15:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - unauthenticated-access
  - browser-control
  - web-application
products:
  - camofox-mcp (< 1.13.2)
references:
  - https://github.com/advisories/GHSA-7hgr-7h44-33w2
rules:
  - title: Detect Unauthenticated HTTP MCP Requests to /mcp
    description: Detects HTTP POST requests to the /mcp endpoint without authorization headers, indicating potential unauthenticated access to browser-control tools.
    platform: sigma
    severity: high
    tactics:
      - execution
    data_sources:
      - webserver
  - title: Detect HTTP MCP Requests to /mcp from Non-Loopback
    description: Detects HTTP POST requests to the /mcp endpoint originating from non-loopback addresses, indicating potential remote exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    data_sources:
      - webserver
rules_count: 2
---

The `camofox-mcp` package exposed a Streamable HTTP MCP endpoint at `/mcp` without requiring authentication. This vulnerability allows any client capable of reaching the `/mcp` endpoint to list and invoke browser-control tools. While the endpoint implemented rate limiting, it lacked proper inbound MCP-layer authentication. If `CAMOFOX_API_KEY` was configured, the server would forward this server-side key to the underlying `camofox-browser` backend, effectively allowing an unauthenticated MCP caller to leverage the server's browser authority without knowing the backend browser API key. The vulnerability existed in commit `10e3ac08cb50d830eb4ee00a789229f02f28a1a4` and was fixed in `v1.13.2` with commit `599f56ee40f8062aeca541c251ed1d39fb437f50`. This is a high severity issue, although default loopback-only deployments reduce the practical risk.

## Attack Chain

1.  Attacker identifies a `camofox-mcp` instance with HTTP mode enabled.
2.  Attacker sends an HTTP POST request to the `/mcp` endpoint.
3.  The server receives the request and creates a `StreamableHTTPServerTransport` without authentication.
4.  The server connects to the transport and handles the request without validating client identity.
5.  The attacker lists available browser-control tools via an MCP command.
6.  The attacker invokes a browser-control tool, such as `create_tab` or `navigate`.
7.  The server forwards the request to the `camofox-browser` backend, using the configured `CAMOFOX_API_KEY`.
8.  The backend executes the command, potentially allowing unauthorized browser automation.

## Impact

An unauthenticated client reaching the HTTP MCP endpoint can control the MCP server's browser tools. Successful exploitation can lead to unauthorized page navigation, tab creation, interaction with authenticated browser contexts, screenshot and content observation, and other browser-automation actions. The vulnerability poses a significant risk when HTTP mode is exposed for remote clients or deployed through Docker/reverse-proxy configurations, particularly if operators assume `CAMOFOX_API_KEY` protects the entire control plane.

## Recommendation

*   Upgrade `camofox-mcp` to version `v1.13.2` or later to incorporate the fix described in the fix notes.
*   Deploy the following Sigma rule to detect unauthenticated requests to the `/mcp` endpoint.
*   Review `camofox-mcp` configurations to ensure that HTTP mode is not exposed without proper authentication mechanisms in place.
*   Monitor webserver logs for HTTP POST requests to `/mcp` (log source: webserver) originating from unexpected IP addresses.
