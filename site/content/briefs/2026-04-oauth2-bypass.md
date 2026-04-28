---
title: OAuth2 Proxy Authentication Bypass Vulnerability (CVE-2026-40575)
slug: 2026-04-oauth2-bypass
description: A critical authentication bypass vulnerability in OAuth2 Proxy (CVE-2026-40575) allows unauthenticated remote attackers to forge headers and access protected resources, impacting system integrity and availability.
date: "2026-04-16T18:06:42Z"
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

A critical authentication bypass vulnerability, CVE-2026-40575, affects OAuth2 Proxy versions 7.5.0 through 7.15.1. OAuth2 Proxy is a reverse proxy and static file server used to secure web applications via OAuth 2.0 and OpenID Connect. When OAuth2 Proxy is deployed with the `--reverse-proxy` flag enabled and utilizes `--skip_auth_routes` or `--skip-auth-regex` for route exclusion, a remote attacker can bypass authentication by forging the `X-Forwarded-Uri` header. This allows unauthorized…
