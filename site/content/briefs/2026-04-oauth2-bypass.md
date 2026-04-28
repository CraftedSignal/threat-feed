---
title: OAuth2 Proxy Authentication Bypass Vulnerability (CVE-2026-40575)
slug: 2026-04-oauth2-bypass
description: A critical authentication bypass vulnerability in OAuth2 Proxy (CVE-2026-40575) allows unauthenticated remote attackers to forge headers and access protected resources, impacting system integrity and availability.
date: "2026-04-16T18:06:42Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - oauth2
  - authentication-bypass
  - cve-2026-40575
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://ccb.belgium.be/advisories/warning-critical-authentication-bypass-oauth2-can-lead-unauthorized-data-access-patch
  - https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago
  - https://www.tenable.com/cve/CVE-2026-40575
rules:
  - title: OAuth2 Proxy Authentication Bypass Attempt
    description: Detects attempts to bypass OAuth2 Proxy authentication by forging the X-Forwarded-Uri header to access protected resources.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: OAuth2 Proxy Potential Authentication Bypass via X-Forwarded-Uri Header
    description: Detects potential authentication bypass attempts in OAuth2 Proxy by monitoring for the presence of the X-Forwarded-Uri header in web server logs, which could indicate header manipulation.
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

A critical authentication bypass vulnerability, CVE-2026-40575, affects OAuth2 Proxy versions 7.5.0 through 7.15.1. OAuth2 Proxy is a reverse proxy and static file server used to secure web applications via OAuth 2.0 and OpenID Connect. When OAuth2 Proxy is deployed with the `--reverse-proxy` flag enabled and utilizes `--skip_auth_routes` or `--skip-auth-regex` for route exclusion, a remote attacker can bypass authentication by forging the `X-Forwarded-Uri` header. This allows unauthorized access to protected routes without a valid session. The vulnerability was disclosed on April 15, 2026, and impacts the integrity and availability of systems. Defenders should prioritize patching to version 7.15.2 or later and properly configuring the `--trusted-proxy-ip` flag.

## Attack Chain

1.  The attacker identifies an OAuth2 Proxy instance running a vulnerable version (7.5.0 - 7.15.1) with `--reverse-proxy` enabled and route skipping configured.
2.  The attacker crafts a malicious HTTP request targeting a protected resource that is intended to be skipped via `--skip_auth_routes` or `--skip-auth-regex`.
3.  The attacker includes the `X-Forwarded-Uri` header in the crafted HTTP request, setting its value to match a skipped route.
4.  The OAuth2 Proxy, due to the vulnerability, incorrectly processes the forged `X-Forwarded-Uri` header.
5.  The OAuth2 Proxy skips the authentication process for the crafted request, bypassing the intended security controls.
6.  The request is forwarded to the backend web application without proper authentication.
7.  The backend web application processes the request, granting the attacker unauthorized access to the protected resource.
8.  The attacker gains access to sensitive data or functionality within the protected resource, potentially leading to data modification or service disruption.

## Impact

Successful exploitation of CVE-2026-40575 allows unauthenticated attackers to bypass authentication and gain unauthorized access to protected resources. This can lead to data breaches, unauthorized modification of data, and disruption of services. While there is no current information available regarding specific victim counts or sectors targeted, the wide usage of OAuth2 Proxy suggests a broad potential impact across various industries that rely on OAuth2 Proxy for securing their web applications. The impact primarily affects integrity and availability.

## Recommendation

*   Immediately upgrade OAuth2 Proxy to version 7.15.2 or later to remediate CVE-2026-40575 as described in the advisory.
*   Configure the `--trusted-proxy-ip` flag with trusted reverse proxy IP addresses or CIDR ranges after upgrading OAuth2 Proxy, as mentioned in the advisory.
*   Deploy the "OAuth2 Proxy Authentication Bypass Attempt" Sigma rule to your SIEM and tune it for your environment to detect exploitation attempts based on forged `X-Forwarded-Uri` headers.
*   Enable web server logging and monitor for requests containing the `X-Forwarded-Uri` header targeting protected resources, as this is a key indicator of potential exploitation as covered in the rule description.
