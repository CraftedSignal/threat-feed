---
title: Authorizer Unvalidated Redirect URI Vulnerability
slug: 2024-01-09-authorizer-redirect-uri
description: Authorizer is vulnerable to unvalidated redirect URI injection in multiple endpoints, allowing attackers to steal password reset tokens, magic link tokens, and full authentication tokens by redirecting users to attacker-controlled sites.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - redirect-uri
  - account-takeover
  - authorization
vendors:
  - Authorizer
products:
  - Authorizer
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-x3f4-v83f-7wp2
iocs:
  - type: url
    value: https://attacker.com/steal
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Redirect URI Parameters
    description: Detects requests to Authorizer endpoints with a suspicious redirect_uri parameter potentially indicating an attempted token theft.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Access Token Leakage via Redirect URI
    description: Detects HTTP requests with an access_token in the redirect URI, indicating potential token leakage.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Authorizer, a Go-based authentication and authorization service, is susceptible to a critical vulnerability affecting versions prior to commit 73679fa. This vulnerability allows attackers to inject arbitrary redirect URIs into several endpoints, including ForgotPassword, MagicLinkLogin, Signup, InviteMembers, OAuthLoginHandler, and VerifyEmailHandler. The root cause is the lack of proper validation of the `redirect_uri` parameter against the configured `AllowedOrigins` in these endpoints. By exploiting this flaw, attackers can redirect users to malicious sites and steal sensitive information such as password reset tokens, magic link tokens, and full authentication tokens (access_token, id_token, refresh_token). This poses a significant threat as it bypasses intended security configurations and can lead to account takeover and unauthorized access.

## Attack Chain

1.  Attacker crafts a malicious URL containing a vulnerable Authorizer endpoint (e.g., ForgotPassword) and injects an attacker-controlled `redirect_uri` pointing to a malicious site (e.g., `https://attacker.com/steal`).
2.  The victim initiates a password reset request, signup, magic link login, or other vulnerable action on the legitimate Authorizer instance.
3.  Authorizer generates a password reset token, magic link token, or full auth tokens and appends it to the attacker-controlled `redirect_uri` without validation.
4.  The victim receives a legitimate email or link from Authorizer containing the malicious URL.
5.  The victim clicks the link, redirecting their browser to the attacker-controlled site.
6.  The attacker-controlled site receives the sensitive token or full auth tokens as URL parameters (e.g., `https://attacker.com/steal?token=<reset_token>` or `https://attacker.com/steal?access_token=<access_token>&id_token=<id_token>&refresh_token=<refresh_token>`).
7.  The attacker harvests the token(s) from the URL.
8.  The attacker uses the stolen token(s) to reset the victim's password, gain unauthorized access to their account, or impersonate the victim.

## Impact

This vulnerability can lead to complete account takeover due to stolen password reset tokens and full session compromise via stolen access tokens, ID tokens, and refresh tokens. It also affects passwordless login mechanisms by compromising magic link tokens. The attacker requires no prior authentication and only needs to trick the victim into clicking a link. This vulnerability affects any Authorizer instance running a vulnerable version, potentially impacting all users of applications relying on the vulnerable Authorizer service. The exposure of tokens in URL parameters also leads to information leakage through browser history, server logs, and referrer headers.

## Recommendation

*   Upgrade Authorizer to a version containing the fix for this vulnerability (>= commit after 73679fa).
*   Implement robust validation of the `redirect_uri` parameter in all affected endpoints, specifically ForgotPassword, MagicLinkLogin, Signup, InviteMembers, OAuthLoginHandler, and VerifyEmailHandler, using a function similar to `validators.IsValidOrigin()` as used in `/app` handler.
*   Modify the default `AllowedOrigins` in `cmd/root.go` to a more restrictive value than `["*"]` to force explicit configuration and prevent the OAuth endpoint's validation from becoming a no-op.
*   Deploy the Sigma rule `Detect Suspicious Redirect URI Parameters` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for requests to the affected Authorizer endpoints containing suspicious `redirect_uri` parameters, using the IOC `https://attacker.com/steal` as a starting point for identifying attacker infrastructure.
