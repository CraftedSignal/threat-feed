---
title: Traefik ForwardAuth Authentication Bypass via Header Spoofing
slug: 2026-04-traefik-auth-bypass
description: Traefik's `ForwardAuth` and snippet-based authentication middleware has a high severity authentication bypass vulnerability because it does not sanitize header aliases with underscores, allowing attackers to spoof trust context and bypass authentication on protected routes.
date: "2026-04-25T12:00:00Z"
lastmod: "2026-08-06T21:30:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*
  - cpe:2.3:a:traefik:traefik:3.7.0:ea1:*:*:*:*:*:*
  - cpe:2.3:a:traefik:traefik:3.7.0:ea2:*:*:*:*:*:*
  - cpe:2.3:a:traefik:traefik:3.7.0:ea3:*:*:*:*:*:*
  - cpe:2.3:a:traefik:traefik:3.7.0:rc1:*:*:*:*:*:*
has_poc: true
tags:
  - authentication-bypass
  - header-injection
  - forwarded-headers
  - traefik
vendors:
  - Traefik
products:
  - Traefik
  - Traefik (v2.11.x <= 2.11.43, v3.6.x <= 3.6.14, v3.7.x <= 3.7.0-rc.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33433
    cvss: 8.8
    epss: 0.00469
  - id: CVE-2026-39858
    cvss: 10
    epss: 0.00479
references:
  - https://github.com/advisories/GHSA-5m6w-wvh7-57vm
  - https://github.com/traefik/traefik/releases/tag/v2.11.43
  - https://github.com/traefik/traefik/releases/tag/v3.6.14
  - https://github.com/traefik/traefik/releases/tag/v3.7.0-rc.2
  - https://github.com/advisories/GHSA-x677-9fxg-v5c5
rules:
  - title: Detect Traefik ForwardAuth Bypass Attempt
    description: Detects attempts to bypass Traefik ForwardAuth by injecting spoofed trust context through underscore-prefixed X-Forwarded-* headers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Traefik ForwardAuth Bypass via X_Forwarded_Scheme
    description: Detects attempts to bypass Traefik ForwardAuth by injecting spoofed trust context through the X_Forwarded_Scheme header.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-08-06T21:30:01Z"
    level: L2
    summary: poc_available; added CVE-2026-33433 +1; traefik version v2.11.x <= 2.11.43, v3.6.x <= 3.6.14, v3.7.x <= 3.7.0-rc.2
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-x677-9fxg-v5c5
---

A high severity authentication bypass vulnerability exists in Traefik versions before 2.11.43, 3.6.14, and 3.7.0-rc.2, affecting the `ForwardAuth` middleware and snippet-based authentication. The vulnerability stems from incomplete sanitization of forwarded headers. Traefik's logic only targets canonical header names like `X-Forwarded-Proto`, failing to strip or normalize alias variants that use underscores instead of dashes (e.g., `X_Forwarded_Proto`). This allows attackers to inject spoofed trust context, such as a trusted scheme or host, through the alias headers. If the authentication backend normalizes underscore and dash header forms equivalently, an attacker can bypass authentication on protected routes without valid credentials. This impacts deployments where authorization decisions rely on forwarded headers.

## Attack Chain

1. An attacker identifies a Traefik instance using `ForwardAuth` or snippet-based authentication.
2. The attacker discovers that the authentication backend normalizes header names, treating `X_Forwarded_Proto` and `X-Forwarded-Proto` as equivalent.
3. The attacker crafts an HTTP request with alias headers, such as `X_Forwarded_Proto: https` and `X_Forwarded_Host: trusted.example`.
4. Traefik receives the request and forwards it to the authentication backend without sanitizing the alias headers.
5. The authentication backend processes the request and normalizes the header names.
6. The authentication backend evaluates trust predicates based on the spoofed values in the alias headers.
7. The authentication backend incorrectly determines that the request is authenticated based on the spoofed trust context.
8. Traefik grants the attacker access to the protected resource, bypassing authentication.

## Impact

This vulnerability allows unauthenticated attackers to bypass authentication and access protected endpoints. In deployments where authorization decisions depend on forwarded headers, attackers can interact with backend services as if they were fully authenticated. This can expose sensitive internal functionality and data, potentially leading to data breaches or unauthorized access to critical systems. Successful exploitation undermines the security provided by `ForwardAuth` and similar authentication mechanisms.

## Recommendation

*   Upgrade Traefik to version 2.11.43, 3.6.14, or 3.7.0-rc.2 or later to address the vulnerability.
*   Implement a unified normalization policy across all forwarded header families, including RFC7239 and `X-Forwarded-*` to remediate the root cause.
*   Deploy the Sigma rule `Detect Traefik ForwardAuth Bypass Attempt` to identify exploitation attempts based on the presence of unusual `X_Forwarded_*` headers.
*   Restrict the headers forwarded to authentication services using an explicit allowlist to minimize the attack surface.
