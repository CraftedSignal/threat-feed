---
title: meta-ads-mcp Authentication Bypass via X-Pipeboard-Token Header
slug: 2026-07-meta-ads-mcp-auth-bypass
description: An authentication bypass vulnerability in `meta-ads-mcp` version 1.0.113 allows unauthenticated network callers to gain unauthorized access by sending an arbitrary value in the `X-Pipeboard-Token` HTTP header, leading to the reuse of the server operator's `META_ACCESS_TOKEN` for full read and write access to Meta Ads data.
date: "2026-07-17T18:51:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - web-vulnerability
  - meta
  - python
  - cwe-287
vendors:
  - Meta
products:
  - meta-ads-mcp (1.0.113)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any network-reachable caller that can send an HTTP request with an arbitrary `X-Pipeboard-Token` header can...
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: No authentication context is set; the token getter falls back to the server operator's `META_ACCESS_TOKEN` environment variable. Every subsequent MCP tool call executes with the operator's Meta credentials...
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Read all Meta Ads data accessible to the server operator (ad accounts, campaigns, creatives, audiences, insights). Write Meta Ads resources (create/update campaigns, ads, budgets) as the operator.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2v2f-mvfg-ph56
---

A critical authentication bypass vulnerability, identified in `meta-ads-mcp` version 1.0.113, enables unauthenticated attackers to gain privileged access to Meta Ads data. This flaw resides within the `AuthInjectionMiddleware` logic, which incorrectly handles the presence of the `X-Pipeboard-Token` HTTP header. If an attacker sends an HTTP POST request to the `/mcp` endpoint with any arbitrary value in this header, the middleware bypasses the authentication check. Consequently, the application's token retrieval mechanism falls back to using the server operator's `META_ACCESS_TOKEN` environment variable. This grants the attacker the ability to read and write all Meta Ads data accessible to the operator. This vulnerability specifically impacts deployments of `meta-ads-mcp` configured in `streamable-http` mode with the `META_ACCESS_TOKEN` environment variable set, which is a documented production setup.

## Attack Chain

1. An unauthenticated attacker sends an HTTP POST request to the `/mcp` endpoint, including an `X-Pipeboard-Token` header with an arbitrary value.
2. The `AuthInjectionMiddleware` in `meta_ads_mcp/core/http_auth_integration.py` evaluates its guard condition (`if not auth_token and not pipeboard_token`). Because `auth_token` is `None` (as `X-Pipeboard-Token` is not recognized by `extract_token_from_headers()`) and `pipeboard_token` is truthy (due to the presence of `X-Pipeboard-Token`), the condition evaluates to `False`, bypassing the intended authentication check.
3. No proper authentication context is established for the incoming request within the application.
4. During subsequent processing, when an access token is required, the application's token getter (`http_auth_integration.py:163-168`) defaults to the original token accessor due to the lack of an `auth_token`.
5. The `auth.py` module (`auth.py:446-453`) retrieves the `META_ACCESS_TOKEN` from the server's environment variables.
6. This operator's `META_ACCESS_TOKEN` is then automatically injected into the `access_token` keyword argument for any invoked `meta_api_tool` (e.g., `api.py:390-396`).
7. The targeted tool, such as `accounts.py:42-62` (`get_ad_accounts`), makes an API call to the Meta Graph API using the operator's `META_ACCESS_TOKEN`.
8. `httpx.AsyncClient` (`api.py:225-235`) sends a privileged HTTP request to the Meta Graph API, allowing the attacker to read and write Meta Ads data with the operator's permissions.

## Impact

Successful exploitation of this authentication bypass allows an unauthenticated network-reachable attacker to fully compromise the `meta-ads-mcp` instance. The attacker gains the ability to read all Meta Ads data (including ad accounts, campaigns, creatives, audiences, and insights) accessible to the server operator. Furthermore, the attacker can write and modify Meta Ads resources, such as creating or updating campaigns and budgets, effectively taking control of the operator's advertising accounts. There is also a risk of exfiltrating the operator's identity through Meta Graph API error responses that might reference the compromised token. This vulnerability directly affects operators using `meta-ads-mcp` in `streamable-http` mode with a configured `META_ACCESS_TOKEN`.

## Recommendation

* Enable comprehensive `webserver` logging that captures all HTTP request headers for all HTTP POST requests to the `/mcp` endpoint.
* Review `webserver` logs for HTTP POST requests to the `/mcp` endpoint containing the `X-Pipeboard-Token` header, as this indicates an attempted authentication bypass.
