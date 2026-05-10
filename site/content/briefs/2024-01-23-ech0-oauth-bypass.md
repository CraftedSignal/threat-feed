---
title: Ech0 OAuth Redirect URI Validation Bypass Vulnerability
slug: 2024-01-23-ech0-oauth-bypass
description: Ech0's OAuth redirect URI validation ignores the path component, allowing attackers to craft malicious redirect URIs for exchange-code theft and potential account takeover.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - oauth
  - redirect_bypass
  - account_takeover
  - web_application
products:
  - github.com/lin-snow/Ech0 (< 1.4.8-0.20260503040728-a7e8b8e84bd1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-p64j-f4x9-wq66
rules:
  - title: Detect Ech0 OAuth Redirect Bypass Attempt
    description: Detects attempts to exploit the Ech0 OAuth redirect bypass vulnerability by identifying requests to the `/oauth/:provider/login` endpoint with a suspicious redirect_uri containing paths other than the allowed ones.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Ech0 OAuth Exchange Code Retrieval via Referer
    description: Detects potential exfiltration of Ech0 OAuth exchange codes via Referer headers by monitoring for requests to attacker-controlled domains originating from the vulnerable Ech0 instance.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in Ech0's OAuth implementation where the `parseAndValidateClientRedirect` function improperly validates redirect URIs. Specifically, the validation logic only checks the scheme and host of the redirect URI against the admin-configured allowlist, neglecting to validate the path, query, or fragment components. This flaw allows an attacker to craft a `redirect_uri` with a valid, allowlisted host but a malicious path. By exploiting this, an attacker can trick a user into completing the OAuth flow, resulting in a redirect to the attacker-controlled path with the one-time exchange code appended in the query string. This code can then be exchanged for the victim's access and refresh tokens, leading to account takeover. Observed in version v4.5.6, this vulnerability highlights a critical flaw in the OAuth implementation.

## Attack Chain

1.  Attacker crafts a malicious link containing a `redirect_uri` parameter. The host in this URI matches an allowed origin, but the path component points to an attacker-controlled location (e.g., `https://myecho.example.com/attacker-chosen-path`).
2.  The victim clicks the malicious link, initiating the OAuth login flow at `/oauth/:provider/login`. The `redirect_uri` is embedded, without validation, into a signed state JWT.
3.  The victim authenticates through the OAuth provider (e.g., GitHub).
4.  Ech0 receives the OAuth callback, extracts the `redirect_uri` from the state JWT, and performs a partial validation (scheme and host only) via `parseAndValidateClientRedirect`.
5.  Because the host matches the allowlist, the validation passes, and Ech0 generates a one-time exchange code.
6.  Ech0 redirects the victim to the attacker-chosen path with the code appended as a query parameter: `https://myecho.example.com/<attacker-path>?code=<one-time-exchange-code>`.
7.  The attacker retrieves the one-time code, either through Referer header leakage, analytics scripts, or an open redirect on the compromised path.
8.  The attacker uses the retrieved code to `POST` to the `/api/auth/exchange` endpoint, obtaining the victim's access and refresh tokens.

## Impact

Successful exploitation allows the attacker to fully compromise the victim's Ech0 account. This can lead to unauthorized access to sensitive data, modification of account settings, and potential further compromise of systems accessible via the compromised account. The attack requires a single click by the victim and leverages common web vulnerabilities like Referer leakage or open redirects. The vulnerability is significant as it violates RFC 6749 §3.1.2, which mandates exact redirect URI matching.

## Recommendation

*   Implement exact redirect URI matching by validating the full URI (scheme, host, and path) in the `parseAndValidateClientRedirect` function. See code example in the advisory.
*   Implement additional input validation of the `redirect_uri` parameter at the login endpoint (`/oauth/:provider/login`) before embedding it in the state JWT, as described in the advisory.
*   Deploy the Sigma rule "Detect Ech0 OAuth Redirect Bypass Attempt" to identify potential exploitation attempts by monitoring for suspicious `redirect_uri` parameters containing paths other than the allowed ones.
*   If using GitHub OAuth, review the allowed return URLs and ensure they are as specific as possible to prevent path-based bypasses.
*   Upgrade to a patched version of Ech0 that addresses this vulnerability. The advisory indicates versions prior to 1.4.8-0.20260503040728-a7e8b8e84bd1 are vulnerable.
