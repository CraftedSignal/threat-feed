---
title: 'CVE-2026-81036: OAuth Redirect Validation Bypass in Stalwart Mail Server'
slug: 2026-08-stalwart-oauth-redirect
description: Stalwart Mail Server suffers from an OAuth open redirect vulnerability in its default configuration that allows attackers to hijack authorization codes and gain unauthorized access to user accounts.
date: "2026-08-26T16:22:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Stalwart Labs
products:
  - Stalwart Mail Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: An attacker can craft a malicious redirect URI, intercept the authorization code after the victim authenticates, and exchange that code for access and refresh tokens, leading to unauthorized account access.
    confidence_band: high
cves:
  - id: CVE-2026-81036
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81036
---

Stalwart Mail Server contains a vulnerability (CVE-2026-81036) in its OAuth implementation where redirect URI targets are not properly validated against registered destinations. The flaw originates in the validation routine located at crates/http/src/auth/oauth/registration.rs. Due to the shipped default configuration having client-authentication requirements disabled, the validation routine returns immediate success for any provided redirect URI. 

The application stores the attacker-supplied redirect value alongside the authorization code. During the authentication process, the application redirects the user's browser to this attacker-controlled destination with the authorization code attached. Because the token exchange endpoint only verifies that the redirect URI presented during the exchange matches the one recorded with the code, the attacker can successfully exchange the code for valid access and refresh tokens, leading to full unauthorized access to the victim's mail account.

## Attack Chain

1. Attacker crafts a malicious request containing a custom 'redirect_uri' parameter pointing to an attacker-controlled endpoint.
2. Attacker induces a victim to initiate an OAuth authentication flow through the vulnerable Stalwart Mail Server.
3. The server processes the OAuth request, fails to validate the redirect URI due to the insecure default configuration, and stores the malicious URI.
4. The victim authenticates successfully via the legitimate OAuth provider.
5. The server sends an HTTP 302 redirect, instructing the victim's browser to send the authorization code to the attacker's server.
6. Attacker captures the authorization code from the incoming request logs.
7. Attacker presents the captured authorization code and the original malicious redirect URI to the Stalwart token endpoint.
8. The server issues valid access and refresh tokens to the attacker, providing unauthorized access to the victim's account.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to intercept authorization codes and exchange them for permanent access and refresh tokens. This results in complete compromise of the victim's email account, enabling exfiltration of sensitive data and continued unauthorized access to the mail service.

## Recommendation

1. Review Stalwart Mail Server configuration files to verify the status of client-authentication requirements.
2. Patch the server to the latest version that enforces strict redirect URI validation regardless of authentication settings.
3. Audit application access logs for unexpected redirect URIs associated with OAuth authentication attempts.
4. Implement strict allowlisting for OAuth redirect URIs if the environment permits, ensuring only trusted destinations are permitted.
