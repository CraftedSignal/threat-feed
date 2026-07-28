---
title: Pterodactyl Panel Global Rate-Limit Vulnerability Enables Unauthenticated DoS (CVE-2026-61609)
slug: 2026-07-pterodactyl-dos
description: An unauthenticated attacker can exploit CVE-2026-61609, a global rate-limit vulnerability in Pterodactyl Panel versions up to and including 1.12.4, by sending approximately 10 requests per minute to authentication endpoints, leading to a panel-wide denial of service for all legitimate users and administrators attempting to log in or complete 2FA.
date: "2026-07-28T15:02:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - web-application
  - pterodactyl
vendors:
  - Pterodactyl
products:
  - Panel (>= 1.7.0, <= 1.12.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: This is a trivially triggered, unauthenticated, panel-wide authentication denial of service.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Transversal
    evidence: The `authentication` rate limiter used for the login and two-factor checkpoint endpoints applies a single global bucket shared by every client, instead of keying per IP or per account.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xvc3-826v-xf47
rules:
  - title: Detect Pterodactyl Panel Global Rate-Limit DoS (CVE-2026-61609)
    description: Detects CVE-2026-61609 exploitation - HTTP POST to Pterodactyl authentication endpoints resulting in 429 Too Many Requests status code, indicating the global rate limit has been exhausted, leading to denial of service.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1498.001
      - T1499
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-61609, has been identified in Pterodactyl Panel versions 1.7.0 through 1.12.4. This flaw allows an unauthenticated attacker to trigger a panel-wide denial of service (DoS) by exploiting an improperly configured rate limiter on the login and two-factor authentication (2FA) checkpoint endpoints. The `authentication` rate limiter, intended to prevent brute-force attacks, uses a single global bucket rather than keying per IP address or per account. This means a low-volume attacker, sending as few as 10 requests per minute from a single IP address, can exhaust this shared bucket. Once exhausted, all subsequent login and 2FA attempts by any user, from any IP address, will receive HTTP 429 "Too Many Requests" responses. This effectively locks out all legitimate users and administrators from accessing the panel, crippling its availability without requiring any prior authentication or complex attack techniques.

## Attack Chain

1. An attacker identifies an internet-facing Pterodactyl panel running a vulnerable version (1.7.0-1.12.4).
2. The attacker crafts HTTP POST requests targeting the `/auth/login/checkpoint` or `/auth/login` endpoints.
3. From a single IP address, the attacker sends approximately 10 requests per minute to these authentication endpoints.
4. Due to the missing `->by($request->ip())` configuration in the `RouteServiceProvider`, the Pterodactyl panel increments a single, global rate-limit counter for all requests to these endpoints.
5. Upon the 11th request within a minute, the global rate limit is exceeded, causing the panel to return HTTP 429 "Too Many Requests" responses for all subsequent requests to `/auth/login` and `/auth/login/checkpoint`.
6. Legitimate users, attempting to log in or complete 2FA, receive HTTP 429 responses regardless of their IP address or correct credentials.
7. The attacker sustains the low-volume rate of 10 requests per minute, perpetually locking out all users and administrators from accessing the Pterodactyl panel.
8. The panel becomes entirely unusable for authentication, resulting in a sustained, unauthenticated, and panel-wide denial of service.

## Impact

This vulnerability poses a severe threat to the availability of affected Pterodactyl panels. An unauthenticated, low-bandwidth attacker can render any internet-facing panel inaccessible for all users, including administrators. The impact is a complete denial of service for authentication, meaning no one can log in or perform 2FA verification. This not only disrupts legitimate user access but also prevents administrators from managing the panel, potentially hindering incident response efforts or critical maintenance. The simplicity and low resource requirement for this attack make it highly attractive for adversaries seeking to cause disruption.

## Recommendation

* **Patch CVE-2026-61609**: Immediately update Pterodactyl Panel to a version greater than 1.12.4, which includes the fix for CVE-2026-61609.
* **Deploy the Sigma rule**: Deploy the "Detect Pterodactyl Panel Global Rate-Limit DoS (CVE-2026-61609)" Sigma rule to your SIEM to detect attempts to exploit CVE-2026-61609 by monitoring webserver logs for HTTP 429 responses on authentication endpoints.
* **Monitor webserver logs**: Actively monitor webserver logs for `POST` requests to `/auth/login` and `/auth/login/checkpoint` that result in `sc-status: 429`, especially from multiple distinct source IPs within a short timeframe, as described in the detection rule.
