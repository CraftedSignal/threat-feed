---
title: tinyauth Authorization Bypass via Case-Sensitive Hostname Matching
slug: 2026-09-tinyauth-bypass
description: An authorization bypass vulnerability in tinyauth allows authenticated users to access restricted applications by manipulating the character casing of the request hostname, causing the service to fail open.
date: "2026-09-23T01:55:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - reverse-proxy
  - identity-management
vendors:
  - steveiliop56
products:
  - tinyauth (< 5.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The authorization bypass allows an authenticated user to gain access to unauthorized resources.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-328g-jx67-v94g
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade tinyauth to 5.1.2
      owner: IT Operations
      due: 24h
      evidence: Patched version 5.1.2 provided in advisory
  hunt_leads:
    - lead: Analyze logs for high frequency of requests to the forward-auth endpoint containing mixed-case hostnames
      technique_id: T1059
      data_needed:
        - Web server access logs from the reverse proxy (Traefik/Nginx/Caddy)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker triggers bypass via mixed-case hostname variation
---

tinyauth is a forward-auth service that acts as a gatekeeper for reverse proxies like Traefik, Caddy, Nginx, and Envoy. It verifies authentication and enforces per-app access control lists (ACLs) based on hostnames. An authorization bypass exists in tinyauth versions prior to 5.1.2 due to case-sensitive string comparisons when matching incoming hostnames against configured ACLs.

Because DNS, HTTP routing, and TLS treat hostnames as case-insensitive, a reverse proxy will correctly route a mixed-case hostname (e.g., `APP.example.com`) to the intended application. However, when tinyauth receives this request, its lookup logic fails to match the hostname because it performs a case-sensitive comparison. When the lookup fails, the application incorrectly falls back to an empty configuration object instead of denying access. This "fail-open" behavior grants authorized status to any already-authenticated user, effectively ignoring any per-app `users`, `groups`, or `ip` allowlists. This vulnerability allows an attacker with a valid session to bypass intended access restrictions for any protected app on the same instance.

## Attack Chain

1. Attacker obtains a valid user session for the target tinyauth instance.
2. Attacker identifies a target application protected by an ACL that explicitly excludes their user account or group.
3. Attacker crafts an HTTP request for the target application using a mixed-case hostname (e.g., `TargetApp.Example.Com` instead of `targetapp.example.com`).
4. The reverse proxy receives the request, ignores the case difference, and routes it to the intended upstream backend.
5. The proxy sends the request to tinyauth via the configured forward-auth endpoint, preserving the mixed-case hostname in the `X-Forwarded-Host` or `Host` header.
6. tinyauth's `GetAccessControls` function attempts to lookup the mixed-case hostname, fails to find a match due to case-sensitive logic, and returns an empty App configuration.
7. The authorization logic evaluates the empty configuration, defaults to "allow," and returns a `200 Authenticated` response to the reverse proxy.
8. The proxy forwards the request to the upstream application, treating the attacker as an authorized user.

## Impact

Successful exploitation allows any authenticated user to bypass per-app access restrictions, gaining full access to the data and functionality of restricted applications. This defeats the product's primary security feature - the per-app trust boundary - within multi-app SSO deployments. Impacted sectors include any organization relying on tinyauth to manage granular access to internal services.

## Recommendation

1. Upgrade tinyauth to version 5.1.2 or later immediately to resolve the case-insensitive matching logic.
2. Audit application access logs for unexpected `200 OK` responses from the forward-auth endpoint that correspond to known restricted users accessing sensitive subdomains.
3. Validate that your reverse proxy configuration and tinyauth instance are correctly synchronized regarding expected domain case-sensitivity.
