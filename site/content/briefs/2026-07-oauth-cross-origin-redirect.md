---
title: Cross-origin OAuth token-request redirects can expose signed request metadata
slug: 2026-07-oauth-cross-origin-redirect
description: The 'oauth' Ruby gem versions 0.5.5 through 1.1.5 are vulnerable to a critical issue (CVE-2026-54605) where the 'OAuth::Consumer#token_request' method improperly handles HTTP 3xx redirects during OAuth 1.0 token exchanges, enabling an attacker to redirect the request to a malicious host, exposing sensitive OAuth 1.0 metadata, and facilitating Server-Side Request Forgery (SSRF) and confused-deputy behavior.
date: "2026-07-28T16:28:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - oauth
  - vulnerability
  - ssrf
  - ruby
  - gem
  - web-application
vendors:
  - ruby-oauth
products:
  - oauth (>= 0.5.5, <= 1.1.5)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The redirected request is signed for the attacker-controlled endpoint... the attacker may receive OAuth 1.0 parameters such as `oauth_consumer_key`, `oauth_signature_method`, `oauth_timestamp`, `oauth_nonce`, `oauth_version`, and `oauth_signature`.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The OAuth client follows the redirect on behalf of the application, so the redirected host is contacted from the application server's network position.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A malicious or compromised token endpoint can cause an otherwise trusted application to initiate signed requests to an unintended origin.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-prq8-7wvh-44qh
  - https://github.com/ruby-oauth/oauth/commit/d74b767f
  - https://github.com/ruby-oauth/oauth2/security/advisories/GHSA-pp92-crg2-gfv9
---

The `oauth` Ruby gem, specifically versions 0.5.5 through 1.1.5, contains a critical vulnerability (CVE-2026-54605) in its `OAuth::Consumer#token_request` method. This flaw allows for cross-origin signed-request disclosure, Server-Side Request Forgery (SSRF), and confused-deputy behavior. When an application uses the gem to request OAuth 1.0 tokens, the `token_request` helper follows HTTP 3xx redirects. If an attacker can control or compromise an OAuth server to return a redirect to a malicious host, the vulnerable gem will re-sign the original token request, including sensitive OAuth 1.0 metadata like `oauth_consumer_key`, `oauth_signature`, `oauth_nonce`, and `oauth_timestamp`, and send it to the attacker-controlled endpoint. This also exposes the application server's network position, enabling SSRF attacks against internal or external targets, and can force the application to make signed requests to unintended origins, leading to confused-deputy scenarios. The vulnerability is due to improper parsing of the `Location` header, lack of redirect limits, and recursive handling of cross-host redirects that mutate the consumer's configured `site`. Patching to version 1.1.6 or later is recommended.

## Attack Chain

1. An application, using the vulnerable `oauth` Ruby gem (v0.5.5-1.1.5), initiates an OAuth 1.0 token request (e.g., `OAuth::Consumer#get_request_token` or `OAuth::Consumer#get_access_token`) to a legitimate OAuth provider.
2. The OAuth provider's token endpoint, either compromised or influenced by an attacker, responds with an HTTP 3xx redirect. This redirect's `Location` header points to an attacker-controlled domain (e.g., `https://attacker.example/...`).
3. The vulnerable `OAuth::Consumer#token_request` method in the `oauth` gem automatically parses the `Location` header, modifies the consumer's `site` configuration to the attacker's domain, and rebuilds its internal HTTP client.
4. The `oauth` gem then recursively attempts the token request, this time targeting the attacker-controlled `site` but still using the application's legitimate OAuth 1.0 consumer key and secrets to sign the request.
5. The application server makes an outbound network connection, sending the newly signed OAuth 1.0 token request, which now includes sensitive parameters like `oauth_consumer_key`, `oauth_signature`, `oauth_nonce`, and `oauth_timestamp`, to the attacker-controlled host.
6. The attacker receives this signed request, gaining access to sensitive integration metadata and potentially discovering internal network services via Server-Side Request Forgery (SSRF) if the attacker's endpoint is crafted to target internal resources from the application server's network position.

## Impact

Successful exploitation of CVE-2026-54605 can result in three main security property losses: **cross-origin signed-request metadata disclosure**, **Server-Side Request Forgery (SSRF) from the application server**, and **confused-deputy behavior**. Attackers can receive sensitive OAuth 1.0 parameters such as `oauth_consumer_key`, `oauth_signature_method`, `oauth_timestamp`, `oauth_nonce`, `oauth_version`, and `oauth_signature`. While the disclosed OAuth 1 signature is bound to the signed request and not a reusable bearer token, it still exposes sensitive integration metadata. SSRF allows the attacker to use the application server's network position to access internal network resources or other targets. Confused-deputy behavior enables a malicious or compromised token endpoint to cause the trusted application to initiate signed requests to unintended origins, potentially granting the attacker unauthorized access or control.

## Recommendation

* Patch the `oauth` Ruby gem to version 1.1.6 or later immediately to address CVE-2026-54605.
* Ensure configured OAuth token endpoints are fixed absolute URLs controlled by a trusted provider, as described in the "Workarounds" section in the source advisory.
* Avoid using tenant-controlled OAuth token endpoint URLs unless the tenant is fully trusted, as outlined in the "Workarounds" section in the source advisory.
* Implement network egress filtering to block outbound application-server traffic to internal metadata services and other sensitive internal addresses, particularly for services interacting with the `oauth` gem.
* Deploy a trusted proxy in front of OAuth providers that explicitly rejects token endpoint redirects to different origins, as described in the "Workarounds" section in the source advisory.
