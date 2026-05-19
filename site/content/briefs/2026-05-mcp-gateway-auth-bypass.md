---
title: MCP Gateway Authority Injection and JWT/Session Bypass via Unauthenticated Router Hairpin
slug: 2026-05-mcp-gateway-auth-bypass
description: The MCP router exposes an initialize method code path that bypasses the gateway JWT session validator and rewrites the upstream :authority header, gated only by a shared header value, allowing attackers to bypass authorization and access backend services.
date: "2026-05-19T19:43:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - authorization-bypass
  - jwt-bypass
vendors:
  - Kuadrant
products:
  - mcp-gateway (<= 0.6.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/advisories/GHSA-g53w-w6mj-hrpp
rules:
  - title: Detect MCP Gateway Authentication Bypass Attempt
    description: Detects attempts to bypass authentication in MCP Gateway by checking for the presence of the 'mcp-init-host' header and the default 'router-key' in web server logs.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect MCP Gateway Authentication Bypass Attempt - Alternate Router Key Header
    description: Detects attempts to bypass authentication in MCP Gateway by checking for the presence of the 'mcp-init-host' header when the router-key header is present.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

The MCP router (ext_proc) in Kuadrant mcp-gateway versions 0.6.1 and earlier exposes an `initialize` method code path that allows for a critical authentication and authorization bypass. This vulnerability stems from the insufficient validation of the `mcp-init-host` header when present in a request. The presence of this header, combined with a correct `router-key` (either the hardcoded "secret-api-key" or a SHA-256 truncation of the `MCPGatewayExtension` UID), bypasses the gateway's JWT session validator. This allows an attacker to rewrite the upstream `:authority` header to an arbitrary value, effectively impersonating any service. This bypasses both the broker's `x-mcp-authorized` capability filter and the gateway's JWT-based session model, granting unauthorized access to backend listeners registered with the gateway.

## Attack Chain

1. The attacker identifies a vulnerable mcp-gateway instance (version <= 0.6.1).
2. The attacker obtains the `router-key`. This is either the default "secret-api-key" or, in controller-managed deployments, the SHA-256 truncation of the `MCPGatewayExtension` UID, which is accessible with `get` permissions or via the `--mcp-router-key` parameter.
3. The attacker crafts a malicious HTTP request containing the `mcp-init-host` header and the correct `router-key` header.
4. The attacker sets the `:authority` header within the crafted request to a desired, potentially sensitive, backend service.
5. The MCP router, upon receiving the request with the `mcp-init-host` and valid `router-key`, bypasses the JWT session validator.
6. The MCP router rewrites the upstream `:authority` header based on the attacker's provided value.
7. The request is forwarded to the targeted backend listener registered with the gateway.
8. The attacker gains unauthorized access to the backend service, effectively bypassing authentication and authorization mechanisms.

## Impact

Successful exploitation of this vulnerability allows attackers to completely bypass authentication and authorization controls in the MCP gateway. This can lead to unauthorized access to sensitive backend services, data exfiltration, and other malicious activities. The critical nature of this vulnerability lies in its ability to grant complete control over the `:authority` header, which is a fundamental component of service identification and routing. If the default `router-key` is in use, any internet-exposed mcp-gateway is trivially vulnerable.

## Recommendation

*   Upgrade Kuadrant mcp-gateway to a version greater than 0.6.1 to patch the vulnerability described in GHSA-g53w-w6mj-hrpp.
*   Rotate the `MCPGatewayExtension` UID, if in use, to invalidate previously exposed `router-key` values.
*   Deploy the Sigma rule "Detect MCP Gateway Authentication Bypass Attempt" to detect attempts to exploit this vulnerability by monitoring for the presence of the `mcp-init-host` header with the default `router-key` value in web server logs.
*   Monitor MCPGatewayExtension resources for unauthorized access that could lead to router-key exposure.
