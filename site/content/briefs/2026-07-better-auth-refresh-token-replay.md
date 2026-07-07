---
title: Better Auth OAuth Refresh Token Replay via Missing Client Authentication (CVE-2026-53512)
slug: 2026-07-better-auth-refresh-token-replay
description: The legacy `oidcProvider` and `mcp` plugins in the `better-auth` library versions prior to 1.6.11 are vulnerable to CVE-2026-53512, an OAuth refresh-token replay attack where the plugins fail to verify the `client_secret` of confidential clients during the `refresh_token` grant, allowing an attacker who obtains a valid `refresh_token` and `client_id` to indefinitely mint new access tokens and impersonate the client for unauthorized resource access.
date: "2026-07-07T20:15:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oauth
  - authentication-bypass
  - vulnerability
  - web
  - better-auth
vendors:
  - better-auth
products:
  - better-auth (< 1.6.11)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker who obtains any valid `refresh_token` (via database read, log capture, browser-side XSS, or CORS-amplified script in the mcp case) and the public `client_id` can mint fresh access tokens and rotated refresh tokens
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pw9m-5jxm-xr6h
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-53512
  - https://datatracker.ietf.org/doc/html/rfc6749#section-6
  - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-4.3
---

A critical vulnerability, CVE-2026-53512, has been identified in the `better-auth` library, affecting applications using the deprecated `oidcProvider()` or `mcp()` plugins in versions prior to `1.6.11`. This flaw stems from a missing client authentication step during the OAuth 2.0 `refresh_token` grant for confidential clients. Unlike the `authorization_code` grant, these plugins failed to verify the `client_secret`, enabling an attacker to replay a stolen `refresh_token` and its corresponding public `client_id` to repeatedly mint new access tokens. The attacker can gain indefinite access to resources with the user's original authorized scope, as token rotation refreshes the expiration window with each call. This significantly impacts any `better-auth` application configured with confidential OAuth clients using the vulnerable plugins.

## Attack Chain

1.  **Initial Access / Credential Acquisition:** An attacker obtains a valid `refresh_token` and the associated public `client_id` for a confidential OAuth client. This could occur through various methods such as a database breach, log file capture, browser-side Cross-Site Scripting (XSS), or via a CORS-amplified script if exploiting the `mcp` endpoint with its wildcard `Access-Control-Allow-Origin: *`.
2.  **Exploitation of Missing Authentication:** The attacker sends a `POST` request to the vulnerable OAuth 2.0 token endpoint (e.g., `/api/auth/oauth2/token` or `/api/auth/mcp/token`) using the stolen `refresh_token` and `client_id`, but crucially, *without* providing the `client_secret`.
3.  **Token Endpoint Bypass:** Due to the flaw in `better-auth` versions prior to 1.6.11, the `oidcProvider` or `mcp` plugins do not enforce `client_secret` verification on the `refresh_token` grant for confidential clients, allowing the unauthenticated request to proceed.
4.  **Access Token Minting:** The vulnerable token endpoint issues a new, valid `access_token` to the attacker, along with a rotated `refresh_token`.
5.  **Indefinite Session Prolongation:** The attacker uses the newly minted `refresh_token` to repeat steps 2-4, effectively resetting the expiration window of the session and gaining indefinite access.
6.  **Resource Access:** With the valid `access_token`, the attacker can impersonate the legitimate client and user, making requests to resource servers to access, modify, or exfiltrate data within the scope of the original user's authorization.

## Impact

The impact of CVE-2026-53512 is significant, primarily leading to indefinite confidential-client impersonation. An attacker who has acquired a single `refresh_token` and the corresponding `client_id` can continuously mint new `access_tokens` and rotate `refresh_tokens`, thereby maintaining persistent unauthorized access without further authentication. Each newly issued `access_token` carries the original user's authorized scope, granting the attacker the ability to read, write, or otherwise manipulate data on resource servers as if they were the legitimate user. This can result in severe data breaches, unauthorized modifications, and complete compromise of data governed by the affected OAuth client's permissions. The vulnerability affects `better-auth` applications leveraging the deprecated `oidcProvider` or `mcp` plugins.

## Recommendation

*   **Upgrade immediately** to `better-auth@1.6.11` or later to apply the official patch for CVE-2026-53512.
*   **Migrate from deprecated plugins** by transitioning from `oidcProvider()` to the canonical `@better-auth/oauth-provider` package, as it enforces client authentication on all grants by default.
*   **Implement network-layer ingress restriction** for `/api/auth/oauth2/token` and `/api/auth/mcp/token` endpoints to known client IPs at the load balancer, which can partially mitigate risk for server-to-server flows.
*   **Force all clients to public + PKCE** by setting every client's `type: "public"` and requiring PKCE, thereby eliminating the `client_secret` for verification where the bug manifests.
*   **For the mcp endpoint specifically**, drop the wildcard CORS header at an upstream proxy and replace it with a tight allowlist to prevent CORS-amplified attacks.
