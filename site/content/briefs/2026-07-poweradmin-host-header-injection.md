---
title: Poweradmin Vulnerable to Host Header Injection in Authentication Redirects
slug: 2026-07-poweradmin-host-header-injection
description: Poweradmin versions earlier than 4.2.4 and from 4.3.0 up to, but not including, 4.3.3 are vulnerable to CVE-2026-54588, a critical Host Header Injection flaw in OIDC, SAML, and logout authentication flows that allows an unauthenticated attacker to manipulate the HTTP_HOST header, poisoning callback URLs to redirect authorization codes to an attacker-controlled server, leading to full account takeover and potential full DNS zone control.
date: "2026-07-28T16:41:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-vulnerability
  - host-header-injection
  - oidc
  - saml
  - account-takeover
  - dns-hijacking
vendors:
  - Poweradmin
products:
  - Poweradmin (< 4.2.4)
  - Poweradmin (>= 4.3.0, < 4.3.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can poison the redirect_uri sent to the Identity Provider, causing the IdP to redirect the victim's authorization code to an attacker-controlled server
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: resulting in full account takeover with no credentials required... The victim's authorization code will be delivered to this URL upon successful authentication.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: 'Defacement: External Defacement'
    evidence: 'A compromised administrator account grants full DNS zone control, enabling: MX hijacking... SPF/DKIM manipulation... Subdomain takeover... SSL certificate theft'
    confidence_band: high
cves:
  - id: CVE-2026-54588
    cvss: 9.6
    epss: 0.00312
references:
  - https://github.com/advisories/GHSA-3735-5339-xfwx
iocs:
  - type: domain
    value: attacker.com
ioc_counts:
  domain: 1
---

A critical Host Header Injection vulnerability, tracked as CVE-2026-54588, has been identified in Poweradmin versions prior to 4.2.4 and from 4.3.0 through 4.3.2. This flaw arises because Poweradmin dynamically constructs callback URLs for its OpenID Connect (OIDC), SAML, and logout authentication processes using the attacker-controlled `HTTP_HOST` request header without proper validation. An unauthenticated attacker can exploit this by sending a specially crafted request with a spoofed `Host` header, causing the Identity Provider (IdP) to redirect a victim's authorization code to an attacker-controlled server. This enables full account takeover without requiring credentials. If the compromised Poweradmin account possesses administrative privileges, attackers can gain full control over DNS zones, leading to severe consequences such as MX hijacking, SPF/DKIM manipulation, subdomain takeovers, and SSL certificate theft.

## Attack Chain

1. Attacker identifies a vulnerable Poweradmin instance (version < 4.2.4 or >= 4.3.0 and < 4.3.3).
2. Attacker crafts an HTTP request to Poweradmin, spoofing the `Host` header (e.g., `Host: attacker.com`) and potentially `X-Forwarded-Proto`.
3. Poweradmin's OIDC service (`OidcService::getCallbackUrl()`), or SAML/Logout services, uses the spoofed `Host` header to construct a malicious `redirect_uri` (e.g., `http://attacker.com/oidc/callback`).
4. Poweradmin then initiates an OAuth 2.0 authorization request, redirecting the victim's browser to the legitimate Identity Provider (IdP) with the malicious `redirect_uri` embedded.
5. The victim authenticates successfully with the IdP.
6. The IdP, trusting the `redirect_uri` provided by Poweradmin, redirects the victim's authorization code to the attacker-controlled server (e.g., `attacker.com/oidc/callback`).
7. The attacker's server captures the authorization code and exchanges it with the IdP for an access token.
8. The attacker uses the stolen access token to gain full authenticated access to the victim's Poweradmin account, achieving full account takeover.

## Impact

The direct impact of this vulnerability is full account takeover of any user in Poweradmin by an unauthenticated attacker. This requires no prior credentials, malware, or existing access. In configurations where Poweradmin serves as the DNS management system, a compromised administrator account grants full control over DNS zones. This can lead to critical consequences, including MX record hijacking (redirecting all inbound email to attacker's servers for intercepting password resets and 2FA codes), manipulation of SPF/DKIM records (enabling spoofed, cryptographically authenticated emails), subdomain takeovers, and SSL certificate theft. The CVSS 3.1 score ranges from 8.2 (High) for standard deployments to 9.3 (Critical) if a misconfigured reverse proxy propagates the spoofed host header.

## Recommendation

* Immediately patch CVE-2026-54588 by upgrading Poweradmin to version 4.2.4 or 4.3.3 or newer.
* As an immediate mitigation for CVE-2026-54588, set the `interface.base_url` parameter in `config/settings.php` to your legitimate Poweradmin URL. This activates a safe branch in `SamlConfigurationService`.
* Implement filtering or validation of the `Host` header at the web server or reverse proxy level to ensure it only accepts requests for expected domain names, especially for applications like Poweradmin that handle authentication.
* Block the indicator `attacker.com` at your network perimeter, including DNS resolvers, web application firewalls, and proxy servers.
