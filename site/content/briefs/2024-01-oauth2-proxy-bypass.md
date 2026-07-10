---
title: OAuth2 Proxy Authentication Bypass via X-Forwarded-Uri Spoofing
slug: 2024-01-oauth2-proxy-bypass
description: OAuth2 Proxy versions 7.5.0 through 7.15.1 are vulnerable to an authentication bypass where attackers can spoof the `X-Forwarded-Uri` header when `--reverse-proxy` is enabled alongside `--skip-auth-regex` or `--skip-auth-route`, allowing unauthorized access to protected resources.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oauth2-proxy
  - authentication-bypass
  - CVE-2026-40575
  - reverse-proxy
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
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40575
rules:
  - title: Detect Suspicious X-Forwarded-Uri Header
    description: Detects requests with a suspicious X-Forwarded-Uri header, potentially indicating an authentication bypass attempt in OAuth2 Proxy.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect X-Forwarded-Uri Header Manipulation
    description: Detects web requests where the X-Forwarded-Uri header is significantly different from the actual request URI, indicating potential spoofing.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OAuth2 Proxy is a reverse proxy that provides authentication using OAuth2 providers. A critical vulnerability, CVE-2026-40575, affects OAuth2 Proxy versions 7.5.0 through 7.15.1. Specifically, when OAuth2 Proxy is configured with the `--reverse-proxy` flag enabled, and also utilizes either `--skip-auth-regex` or `--skip-auth-route` for specifying paths that should bypass authentication, an attacker can manipulate the `X-Forwarded-Uri` HTTP header. This manipulation allows the attacker to spoof the URI used for authentication checks, potentially bypassing authentication and gaining unauthorized access to protected routes. The vulnerability impacts deployments that rely on client-supplied `X-Forwarded-Uri` headers and is patched in version 7.15.2. Defenders should prioritize upgrading to the patched version or implementing the recommended mitigations to prevent unauthorized access.

## Attack Chain

1. The attacker identifies an OAuth2 Proxy instance running a vulnerable version (7.5.0-7.15.1) with `--reverse-proxy` enabled and `--skip-auth-regex` or `--skip-auth-route` configured.
2. The attacker crafts a malicious HTTP request with a spoofed `X-Forwarded-Uri` header. The spoofed URI is chosen to match a `--skip-auth-regex` or `--skip-auth-route` rule.
3. The attacker sends the malicious request to the OAuth2 Proxy instance.
4. OAuth2 Proxy processes the request and evaluates the authentication and skip-auth rules against the spoofed URI from the `X-Forwarded-Uri` header.
5. Due to the spoofed URI matching a skip-auth rule, OAuth2 Proxy bypasses authentication for the request.
6. OAuth2 Proxy forwards the request to the upstream application, without proper authentication checks.
7. The upstream application processes the request, granting the attacker access to protected resources without valid credentials.
8. The attacker gains unauthorized access to sensitive data or functionality that should have been protected by authentication.

## Impact

Successful exploitation of CVE-2026-40575 allows an unauthenticated remote attacker to bypass authentication and access protected routes without a valid session. This can lead to unauthorized access to sensitive data, modification of critical configurations, or execution of privileged operations within the targeted application. The impact is particularly severe for deployments that rely on OAuth2 Proxy for securing critical services and applications, potentially leading to significant data breaches and service disruptions. The exact number of potential victims is unknown but any deployment matching the vulnerable configuration is at risk.

## Recommendation

*   Immediately upgrade OAuth2 Proxy to version 7.15.2 to patch CVE-2026-40575.
*   Implement mitigations if immediate upgrade is not possible: strip client-provided `X-Forwarded-Uri` headers at the reverse proxy or load balancer level.
*   Explicitly overwrite `X-Forwarded-Uri` with the actual request URI before forwarding requests to OAuth2 Proxy as mentioned in the advisory.
*   Restrict direct client access to OAuth2 Proxy so it can only be reached through a trusted reverse proxy.
*   Deploy the Sigma rule `Detect Suspicious X-Forwarded-Uri Header` to monitor for potential exploitation attempts.
