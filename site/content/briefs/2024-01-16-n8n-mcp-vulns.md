---
title: n8n-mcp Vulnerable to Path Traversal, SSRF, and Telemetry Exposure
slug: 2024-01-16-n8n-mcp-vulns
description: n8n-mcp versions before 2.50.1 are vulnerable to path traversal, redirect-following SSRF, and telemetry payload exposure, potentially leading to sensitive information disclosure and unauthorized access.
date: "2026-05-08T17:00:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - ssrf
  - telemetry
  - information-disclosure
vendors:
  - N8N
products:
  - n8n-mcp (< 2.50.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery
references:
  - https://github.com/advisories/GHSA-8g7g-hmwm-6rv2
rules:
  - title: Detect n8n-mcp Path Traversal in cs-uri-stem
    description: Detects potential path traversal attempts in n8n-mcp via suspicious characters in the cs-uri-stem.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect n8n-mcp SSRF via Redirect Following
    description: Detects potential SSRF attempts in n8n-mcp by monitoring for connections to unusual domains after an initial connection to a validated domain.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

`n8n-mcp` versions prior to 2.50.1 are susceptible to three distinct vulnerabilities affecting deployments that leverage the n8n API integration. The first issue involves a lack of validation for caller-supplied identifiers used as URL path segments, enabling authenticated MCP callers to manipulate workflow IDs and direct outbound requests with the configured n8n API key to unintended same-origin endpoints, effectively bypassing access controls. The second vulnerability arises from validated webhook, form, and chat trigger URLs following redirects, potentially redirecting outbound requests to untrusted hosts and exposing the response body to the caller as a non-blind SSRF. Finally, the default opt-in telemetry feature stores unredacted operation payloads, which may contain sensitive information like bearer tokens, API keys, and webhook secrets from workflow node parameters. Successful exploitation of these vulnerabilities could lead to sensitive data exposure and unauthorized access to internal resources.

## Attack Chain

1. An attacker gains authenticated access to the n8n-mcp instance.
2. The attacker crafts a malicious workflow ID containing path traversal characters.
3. The attacker makes an MCP call using the crafted workflow ID.
4. The n8n-mcp instance, lacking proper validation, incorporates the malicious ID into the outbound URL path.
5. The n8n-mcp instance initiates an HTTP request using the constructed URL, including the configured n8n API key.
6. The request is redirected to a different endpoint within the same origin.
7. The attacker gains access to resources or performs actions on the redirected endpoint, bypassing intended access controls.

## Impact

Successful exploitation of these vulnerabilities could lead to significant damage. The path traversal and SSRF vulnerabilities can allow attackers to bypass access controls and gain unauthorized access to internal resources, potentially leading to data breaches or system compromise. The exposure of sensitive information in telemetry data can compromise API keys, secrets, and other credentials, enabling further attacks and unauthorized access to external services. While specific victim counts are unavailable, organizations using affected versions of n8n-mcp are at risk.

## Recommendation

*   Upgrade to `n8n-mcp >= 2.50.1` to remediate the vulnerabilities (see Patched versions).
*   Apply network access restrictions (firewall, reverse-proxy ACL, or VPN) to the MCP HTTP port, allowing only trusted callers to access it, mitigating issues (1) and (2). Alternatively, switch to stdio mode to eliminate the HTTP attack surface (see Workarounds).
*   Disable telemetry by setting `N8N_MCP_TELEMETRY_DISABLED=true` in the environment before starting the server, or run `npx n8n-mcp telemetry disable` once, addressing issue (3) (see Workarounds).
*   Monitor network traffic for unexpected outbound connections originating from the n8n-mcp instance, potentially indicating SSRF attempts.
