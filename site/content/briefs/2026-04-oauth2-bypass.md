---
title: OAuth2 Proxy Authentication Bypass via User-Agent Header
slug: 2026-04-oauth2-bypass
description: A critical authentication bypass vulnerability (CVE-2026-34457) exists in OAuth2 Proxy when used with `auth_request`-style integration and either `--ping-user-agent` is set or `--gcp-healthchecks` is enabled, allowing unauthenticated access to protected resources.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
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

OAuth2 Proxy is vulnerable to an authentication bypass (CVE-2026-34457) when configured with `auth_request`-style integration (e.g., nginx `auth_request`) and either the `--ping-user-agent` option is set or `--gcp-healthchecks` is enabled. This flaw allows an unauthenticated remote attacker to gain unauthorized access to protected upstream resources. The vulnerability exists because OAuth2 Proxy incorrectly treats requests with the configured health check `User-Agent` value as legitimate health checks, irrespective of the requested path. This bypasses the normal login flow, granting access without proper authentication. Versions prior to v7.15.2 are affected, alongside versions <= 3.2.0. Defenders must take immediate action to remediate affected deployments.

## Attack Chain

1.  Attacker identifies an OAuth2 Proxy deployment utilizing `auth_request` and either `--ping-user-agent` or `--gcp-healthchecks`.
2.  Attacker determines the configured `--ping-user-agent` value or identifies that `--gcp-healthchecks` is enabled (default User-Agent: GoogleHC/1.0).
3.  Attacker crafts an HTTP request to a protected resource, setting the `User-Agent` header to the configured `--ping-user-agent` value (or "GoogleHC/1.0" if `--gcp-healthchecks` is enabled).
4.  The reverse proxy (e.g., Nginx) forwards the request to the OAuth2 Proxy's `/oauth2/auth` endpoint.
5.  OAuth2 Proxy incorrectly interprets the request as a health check due to the matching `User-Agent` header.
6.  OAuth2 Proxy responds to the reverse proxy with a 200 OK status, indicating successful authentication.
7.  The reverse proxy, believing the authentication was successful, forwards the attacker's request to the protected upstream resource.
8.  Attacker successfully accesses the protected resource without authenticating, achieving unauthorized access.

## Impact

Successful exploitation of this vulnerability results in complete authentication bypass, granting attackers unauthorized access to sensitive resources protected by OAuth2 Proxy. The number of affected deployments is unknown, but any organization using OAuth2 Proxy with the specified configurations is potentially at risk. This can lead to data breaches, service disruption, and other severe security incidents.

## Recommendation

*   Upgrade to OAuth2 Proxy version `v7.15.2` or later to patch CVE-2026-34457.
*   Disable the `--gcp-healthchecks` flag if it is enabled.
*   Remove any configured `--ping-user-agent` flag.
*   Implement reverse proxy configurations, such as the provided Nginx example, to prevent forwarding client-controlled `User-Agent` headers to the OAuth2 Proxy `/oauth2/auth` endpoint.
*   Deploy the Sigma rule "OAuth2 Proxy Authentication Bypass Attempt" to detect malicious requests exploiting this vulnerability.
