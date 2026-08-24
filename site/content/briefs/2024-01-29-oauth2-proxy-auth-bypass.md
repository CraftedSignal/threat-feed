---
title: OAuth2 Proxy Authentication Bypass via X-Forwarded-Uri Header Spoofing
slug: 2024-01-29-oauth2-proxy-auth-bypass
description: OAuth2 Proxy is vulnerable to an authentication bypass when configured with `--reverse-proxy` and `--skip_auth_routes` or `--skip_auth_regex`; by spoofing the `X-Forwarded-Uri` header, an attacker can bypass authentication and access protected routes without a valid session.
date: "2024-01-29T12:00:00Z"
lastmod: "2026-08-24T20:03:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:oauth2_proxy_project:oauth2_proxy:*:*:*:*:*:*:*:*
tags:
  - oauth2-proxy
  - authentication-bypass
  - reverse-proxy
  - header-spoofing
vendors:
  - OAuth2 Proxy
products:
  - OAuth2 Proxy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40575
    cvss: 9.1
    epss: 0.00477
  - id: CVE-2026-76835
    cvss: 9.1
references:
  - https://github.com/advisories/GHSA-7x63-xv5r-3p2x
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76835
rules:
  - title: Detect X-Forwarded-Uri Header Present in Request to OAuth2 Proxy
    description: Detects requests to OAuth2 Proxy that contain the X-Forwarded-Uri header, which could indicate an attempt to exploit the authentication bypass vulnerability (CVE-2026-40575).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Direct Client Access to OAuth2 Proxy
    description: Detects connections to OAuth2 Proxy originating from outside the defined trusted proxy IP range.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - linux
rules_count: 2
updates:
  - at: "2026-08-24T20:03:09Z"
    level: L2
    summary: added CVE-2026-40575 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76835
---

OAuth2 Proxy versions before 7.15.2 are susceptible to an authentication bypass vulnerability (CVE-2026-40575) when configured with both the `--reverse-proxy` flag and either `--skip_auth_routes` or `--skip_auth_regex`. This configuration flaw allows an attacker to spoof the `X-Forwarded-Uri` header, tricking OAuth2 Proxy into evaluating authentication and skip-auth rules against an attacker-controlled path rather than the actual request URI. The vulnerability exists because OAuth2 Proxy trusts client-supplied `X-Forwarded-Uri` headers. Version 7.15.2 introduces the `--trusted-proxy-ip` flag to mitigate this issue by allowing administrators to specify trusted reverse proxy IPs. However, upgrading alone is insufficient; the `--trusted-proxy-ip` flag must be configured, and additional mitigation steps are recommended to properly secure deployments.

## Attack Chain

1.  The attacker identifies an OAuth2 Proxy instance configured with `--reverse-proxy` and `--skip_auth_routes` (or `--skip_auth_regex`).
2.  The attacker crafts a malicious HTTP request targeting a protected route.
3.  The attacker adds an `X-Forwarded-Uri` header to the request, setting its value to a path configured in `--skip_auth_routes`.
4.  The reverse proxy forwards the request, including the attacker-controlled `X-Forwarded-Uri` header, to the OAuth2 Proxy instance.
5.  OAuth2 Proxy evaluates the `X-Forwarded-Uri` header against the `--skip_auth_routes` rules and incorrectly determines that authentication is not required.
6.  OAuth2 Proxy forwards the request, now bypassing authentication, to the upstream application.
7.  The upstream application processes the request, granting the attacker unauthorized access to the protected resource.
8.  The attacker successfully accesses the protected route and performs unauthorized actions.

## Impact

Successful exploitation of this vulnerability (CVE-2026-40575) allows unauthenticated remote attackers to bypass authentication and access protected routes without valid credentials. This could lead to complete compromise of the application behind the OAuth2 Proxy instance, including data theft, modification, or service disruption. The severity is critical as it directly undermines the authentication mechanism, potentially affecting any organization using OAuth2 Proxy with the vulnerable configuration. The number of affected organizations is currently unknown, but any deployment meeting the criteria is vulnerable.

## Recommendation

*   Upgrade OAuth2 Proxy to version 7.15.2 or later and configure the `--trusted-proxy-ip` flag to explicitly define trusted reverse proxy IPs to mitigate CVE-2026-40575.
*   Implement reverse proxy or load balancer rules to strip or overwrite the `X-Forwarded-Uri` header from client requests, ensuring OAuth2 Proxy receives the correct request URI, as shown in the nginx example.
*   Restrict direct client access to OAuth2 Proxy, ensuring it can only be reached through a trusted reverse proxy to prevent attackers from directly injecting malicious headers.
*   Review and narrow `--skip-auth-route` / `--skip-auth-regex` rules where possible to minimize the attack surface and reduce the potential for authentication bypass.
