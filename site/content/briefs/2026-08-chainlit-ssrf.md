---
title: Unauthenticated SSRF in Chainlit MCP Component
slug: 2026-08-chainlit-ssrf
description: Chainlit versions 2.4.0rc0 through 2.11.1 contain an unauthenticated SSRF vulnerability (CVE-2026-45019) in the Model Context Protocol (MCP) component, allowing attackers to perform internal network reconnaissance and interact with internal APIs using attacker-controlled HTTP headers.
date: "2026-08-26T00:51:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - mcp
  - cve-2026-45019
products:
  - Chainlit (2.4.0rc0 - 2.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can force the Chainlit server to make outbound HTTP requests.
    confidence_band: high
cves:
  - id: CVE-2026-45019
    cvss: 7.2
references:
  - https://github.com/advisories/GHSA-hvfh-5mj3-5f3j
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45019
rules:
  - title: Detect Chainlit Unauthenticated MCP SSRF Attempt
    description: Detects exploitation attempts against CVE-2026-45019 by identifying POST requests to the /mcp endpoint, which should be restricted or disabled if not explicitly needed.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Chainlit, an open-source framework for building LLM chat interfaces, is vulnerable to a severe Server-Side Request Forgery (SSRF) flaw when the Model Context Protocol (MCP) feature is enabled. The vulnerability exists in the `POST /mcp` endpoint, which handles `sse` and `streamable-http` transports. When enabled via `features.mcp.enabled = true`, the application fails to validate the `url` parameter and improperly forwards a user-supplied `headers` dictionary to the internal HTTP client.

An unauthenticated remote attacker can force the Chainlit server to execute arbitrary outbound HTTP requests. Because the server forwards attacker-supplied headers, including `Authorization` and `Cookie`, this vulnerability allows for unauthorized state-changing operations against internal services and provides a mechanism to probe sensitive cloud metadata endpoints (e.g., 169.254.169.254). The issue impacts all versions from 2.4.0rc0 up to, but not including, 2.12.0. Chainlit has addressed this by introducing a strict allowlist-based configuration model in version 2.12.0.

## Attack Chain

1. Attacker establishes a connection to the target Chainlit server via Socket.IO or direct HTTP POST to `/mcp`.
2. Attacker crafts a JSON payload for the `/mcp` endpoint specifying `clientType` as `sse` or `streamable-http`.
3. Attacker injects a malicious `url` parameter (e.g., pointing to an internal admin API or metadata service).
4. Attacker includes a `headers` dictionary in the JSON payload containing sensitive authentication tokens or forged cookies.
5. Chainlit backend receives the request and directly invokes the internal `sse_client` or `streamablehttp_client` using the unsanitized parameters.
6. The server initiates an outbound HTTP request from its local context to the specified internal target.
7. Internal service processes the forged request, effectively bypassing intended authentication/authorization constraints.
8. Attacker achieves unauthorized state change or sensitive data exfiltration against internal infrastructure.

## Impact

Successful exploitation allows an unauthenticated attacker to bypass perimeter security to reach internal networks, probe cloud metadata endpoints, and perform state-changing operations against internal APIs. The lack of validation on both the target URL and the forwarded headers means an attacker can authenticate requests as the Chainlit server itself to downstream services. The impact is critical for deployments running in trusted internal network zones or cloud environments where the server instance holds identity-based permissions (e.g., IAM roles).

## Recommendation

* Upgrade all Chainlit deployments to version 2.12.0 immediately to implement the new strict allowlist-based MCP configuration.
* If immediate patching is not possible, set `features.mcp.enabled = false` in `.chainlit/config.toml` to disable the vulnerable component.
* Restrict outbound network egress for the host running the Chainlit process, specifically blocking access to private IP ranges and the cloud metadata service (169.254.169.254).
* Monitor server-side web logs for `POST` requests to the `/mcp` endpoint originating from unexpected or untrusted sources.
* Enable authentication callbacks for the application to ensure that `/mcp` endpoints are not accessible to unauthenticated sessions.
