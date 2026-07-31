---
title: Unauthenticated Remote Execution in dynatrace-mcp-server HTTP Transport
slug: 2026-07-dynatrace-mcp-unauth-access
description: The dynatrace-mcp-server package v1.8.5 contains a critical authentication bypass vulnerability in its HTTP transport mode that allows unauthenticated, network-reachable attackers to invoke sensitive Model Context Protocol tools.
date: "2026-07-31T19:30:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - mcp
  - dynatrace
  - web-vulnerability
vendors:
  - Dynatrace
products:
  - dynatrace-mcp-server (v1.8.5)
references:
  - https://github.com/advisories/GHSA-p7w7-4929-vpj5
rules:
  - title: Detect Unauthenticated MCP HTTP Requests
    description: Detects potential exploitation attempts by identifying HTTP POST requests to the root endpoint that do not contain an Authorization header.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The `@dynatrace-oss/dynatrace-mcp-server` package, specifically version 1.8.5, contains a critical security vulnerability arising from its implementation of the HTTP transport mode. When the server is initialized with the `--http` flag, it creates a `StreamableHTTPServerTransport` that fails to implement any form of authentication, session validation, or host/origin verification. Consequently, the server accepts raw JSON-RPC `tools/call` requests from any network-reachable source without requiring an `Authorization` header.

Successful exploitation allows an unauthenticated attacker to execute arbitrary Model Context Protocol (MCP) tools under the context of the configured Dynatrace credentials. High-impact tools such as `execute_dql` allow for the exfiltration of sensitive observability data, including logs, security events, and user session information. Additionally, the `create_dynatrace_notebook` tool permits unauthorized modification of tenant data. Deployments utilizing `--host 0.0.0.0` are particularly susceptible, as the vulnerability is exposed to all network interfaces.

## Attack Chain

1. Attacker identifies a reachable `dynatrace-mcp-server` instance listening on the configured HTTP port (e.g., 3999).
2. Attacker probes the endpoint with a JSON-RPC request to confirm the server is running in `--http` mode.
3. Attacker crafts a malicious `tools/call` JSON-RPC payload targeting high-impact functionality such as `execute_dql`.
4. Attacker transmits the payload via an HTTP POST request to the server root, omitting any `Authorization` or `Bearer` token headers.
5. The server's `StreamableHTTPServerTransport` handler parses the request body and executes the function call using the server's pre-configured `DT_PLATFORM_TOKEN`.
6. The `execute_dql` tool executes the attacker-supplied DQL query against the Dynatrace environment.
7. Results from the query are returned directly to the attacker in the HTTP response body, facilitating unauthorized data exfiltration.

## Impact

The vulnerability represents a complete bypass of authentication for sensitive observability functions. Organizations running this server in containerized environments or on multi-tenant networks are at high risk. Successful exploitation grants attackers the ability to query logs, security events, and user metadata, as well as the ability to inject malicious or unauthorized notebook content into the Dynatrace tenant. Given the lack of required interaction and the sensitivity of the data involved, this flaw provides a direct path for data exfiltration and integrity compromise.

## Recommendation

* Immediately restrict network access to the `dynatrace-mcp-server` HTTP port via firewall rules to ensure it is not reachable from untrusted networks.
* Update to the latest version of `dynatrace-mcp-server` or apply the manual remediation provided in the source which implements a timing-safe bearer token validation check for HTTP requests.
* Deploy the provided Sigma rule to your SIEM to detect inbound HTTP requests targeting the `/` endpoint that lack `Authorization` headers.
* Monitor webserver/proxy logs for suspicious POST requests to the MCP server endpoint, particularly those involving `execute_dql` or `create_dynatrace_notebook` in the JSON-RPC method or parameter fields.
