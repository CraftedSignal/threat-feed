---
title: OAuth2 Proxy Authentication Bypass via User-Agent Header
slug: 2026-04-oauth2-bypass
description: A critical authentication bypass vulnerability (CVE-2026-34457) exists in OAuth2 Proxy when used with `auth_request`-style integration and either `--ping-user-agent` is set or `--gcp-healthchecks` is enabled, allowing unauthenticated access to protected resources.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - oauth2-proxy
  - authentication-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5hvv-m4w4-gf6v
rules:
  - title: OAuth2 Proxy Authentication Bypass Attempt
    description: Detects attempts to bypass authentication in OAuth2 Proxy by using the health check User-Agent header.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: OAuth2 Proxy Auth Request with Modified User-Agent
    description: Detects auth_request calls with a static user-agent header, potentially indicating a mitigation is in place.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OAuth2 Proxy is vulnerable to an authentication bypass (CVE-2026-34457) when configured with `auth_request`-style integration (e.g., nginx `auth_request`) and either the `--ping-user-agent` option is set or `--gcp-healthchecks` is enabled. This flaw allows an unauthenticated remote attacker to gain unauthorized access to protected upstream resources. The vulnerability exists because OAuth2 Proxy incorrectly treats requests with the configured health check `User-Agent` value as legitimate health…
