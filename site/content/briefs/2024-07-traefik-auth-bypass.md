---
title: Traefik ForwardAuth Authentication Bypass via X-Forwarded-Prefix Spoofing
slug: 2024-07-traefik-auth-bypass
description: A high-severity authentication bypass vulnerability exists in Traefik's `ForwardAuth` middleware when `trustForwardHeader=false` is configured and Traefik is deployed behind a trusted upstream proxy; Traefik fails to sanitize the `X-Forwarded-Prefix` header, allowing attackers to spoof a trusted prefix value and gain unauthorized access to protected backend routes.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - traefik
  - authentication-bypass
  - webserver
vendors:
  - Traefik
products:
  - Traefik
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-6384-m2mw-rf54
rules:
  - title: Detect Suspicious X-Forwarded-Prefix Header in Traefik Access Logs
    description: Detects requests with a suspicious X-Forwarded-Prefix header targeting the /forbidden path, potentially indicating an authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious X-Forwarded-Prefix Value
    description: Detects requests containing '/admin' in the X-Forwarded-Prefix Header.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical authentication bypass vulnerability impacts Traefik instances utilizing the `ForwardAuth` middleware with `trustForwardHeader=false`, when deployed behind a trusted upstream proxy. This vulnerability arises from Traefik's failure to properly sanitize the `X-Forwarded-Prefix` header. Although Traefik correctly rebuilds other `X-Forwarded-*` headers like `X-Forwarded-For` and `X-Forwarded-Host`, it does not strip or rebuild `X-Forwarded-Prefix`. An attacker can inject a malicious `X-Forwarded-Prefix` value, which is then passed to the authentication service in the subrequest. If the authentication service relies on the `X-Forwarded-Prefix` header for authorization decisions, an attacker can bypass access controls and reach protected backend routes. This issue affects Traefik versions v2.11.x before v2.11.43, v3.6.x before v3.6.14, and v3.7.0-rc.1.

## Attack Chain

1. An attacker sends a request with a crafted `X-Forwarded-Prefix` header (e.g., `X-Forwarded-Prefix: /admin`) to a trusted upstream proxy (e.g., nginx).
2. The trusted proxy forwards the request to the Traefik instance.
3. Traefik's `StripPrefix` middleware processes the request, stripping a configured prefix (e.g., `/forbidden`) and appending it to the `X-Forwarded-Prefix` header using `Header.Add`.
4. The `ForwardAuth` middleware creates a subrequest to the authentication service, copying all incoming headers, including the attacker-controlled `X-Forwarded-Prefix` and the `StripPrefix`-added value.
5. The authentication service receives the subrequest with the concatenated `X-Forwarded-Prefix` values, where the attacker's value appears first (e.g., `X-Forwarded-Prefix: /admin, /forbidden`).
6. The authentication service incorrectly uses the attacker-supplied `/admin` prefix to make authorization decisions.
7. The authentication service authorizes the request due to the spoofed prefix.
8. Traefik forwards the request to the protected backend route, granting the attacker unauthorized access.

## Impact

Successful exploitation allows unauthenticated attackers to bypass access controls and gain unauthorized access to protected backend routes. This can lead to data breaches, unauthorized modification of resources, and other security compromises. The impact is especially severe in environments where `StripPrefix` is used before `ForwardAuth`, and where the authentication service relies heavily on the `X-Forwarded-Prefix` header for authorization decisions. The number of affected deployments is unknown but likely significant, given Traefik's popularity as a reverse proxy and load balancer.

## Recommendation

*   Upgrade to Traefik version v2.11.43, v3.6.14, or v3.7.0-rc.2 or later to patch the vulnerability.
*   As a workaround, if upgrading is not immediately feasible, configure your authentication service to validate and sanitize the `X-Forwarded-Prefix` header, ensuring it only trusts values originating from the trusted proxy.
*   Implement the following Sigma rule to detect suspicious requests with the `X-Forwarded-Prefix` header targeting the `/forbidden` path, indicating potential exploitation attempts.
*   Review and harden your Traefik configuration to ensure that the `trustForwardHeader` parameter is appropriately set based on your deployment environment and trust relationships.
*   Monitor Traefik access logs for suspicious activity, especially requests with unusual `X-Forwarded-Prefix` values, using the `webserver` log source.
