---
title: Vikunja Permissive CORS Policy Leading to Account Compromise
slug: 2026-10-vikunja-cors-misconfiguration
description: Vikunja versions 2.2.0 through 2.6.0 contain a CORS misconfiguration that implicitly trusts all localhost ports, allowing local attackers to retrieve valid bearer tokens via credentialed cross-origin requests.
date: "2026-10-09T21:23:47Z"
lastmod: "2026-10-09T21:25:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vikunja:vikunja:*:*:*:*:*:*:*:*
tags:
  - web-application
  - cors
  - privilege-escalation
  - account-takeover
  - denial-of-service
  - memory-exhaustion
  - vikunja
  - migration
  - resource-exhaustion
  - api
  - dos
  - web-vulnerability
  - credential-access
  - vulnerability
vendors:
  - Vikunja
products:
  - Vikunja (>= 2.2.0, <= 2.6.0)
  - Vikunja (> 2.5.0)
  - Vikunja (<= 2.5.0)
  - Vikunja (<= 2.3.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: An attacker running a malicious service on any port on the same machine as a logged-in user can perform a cross-origin 'fetch' to the token refresh endpoint.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker-operated public Planka URL and token... can therefore drive memory beyond any finite service allocation.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Vikunja stores password-reset, email-confirmation, and account-deletion tokens in the user_tokens table in plaintext.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m687-p538-r5hp
  - https://github.com/go-vikunja/vikunja/blob/a881ac39eecd07575a5aede8e74727c28d5fd578/pkg/routes/api/v1/login.go#L129-L150
  - https://github.com/advisories/GHSA-wq92-8x3r-fm38
  - https://github.com/advisories/GHSA-pqf9-h8g4-8gmh
  - https://github.com/advisories/GHSA-w7jp-mf2v-8342
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91979
  - https://github.com/advisories/GHSA-r6w9-259g-gwrv
updates:
  - at: "2026-10-09T21:24:27Z"
    level: L1
    summary: added coverage for Vikunja (> 2.5.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-wq92-8x3r-fm38
  - at: "2026-10-09T21:24:35Z"
    level: L1
    summary: added coverage for Vikunja (<= 2.5.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-pqf9-h8g4-8gmh
  - at: "2026-10-09T21:24:47Z"
    level: L1
    summary: added coverage for Vikunja (<= 2.5.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-w7jp-mf2v-8342
  - at: "2026-10-09T21:25:11Z"
    level: L2
    summary: added coverage for Vikunja (<= 2.3.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-r6w9-259g-gwrv
---

Vikunja versions 2.2.0 through 2.6.0 are affected by a permissive Cross-Origin Resource Sharing (CORS) policy vulnerability. The application defaults to allowing `http://127.0.0.1:*` and `http://localhost:*` as trusted origins. Crucially, when an administrator configures the required `service.publicurl` for production, this value is appended to - rather than replacing - the existing localhost defaults. Because the application enables `Access-Control-Allow-Credentials: true` and marks refresh cookies as `SameSite=None`, any web page running on the victim's local machine (on any port) can send a credentialed request to the Vikunja API. An attacker can exploit this by forcing a victim's browser to perform a cross-origin `POST` request to the `/api/v1/user/token/refresh` endpoint, which returns a valid bearer JWT in the response body. The resulting token grants the attacker full administrative or user authority over the victim's account.

## Attack Chain

1. The victim logs into their production Vikunja instance, resulting in a persistent `vikunja_refresh_token` cookie being set with `SameSite=None` and `Secure` attributes.
2. The victim visits a malicious or compromised website running on any local port (e.g., `http://localhost:31337`).
3. The malicious site initiates a `fetch()` request to the victim's authenticated Vikunja instance, specifically targeting `POST /api/v1/user/token/refresh`.
4. The victim's browser, observing the `Access-Control-Allow-Credentials: true` header returned by the Vikunja server, attaches the `vikunja_refresh_token` cookie to the cross-origin request.
5. The Vikunja server validates the cookie, processes the request as a legitimate refresh attempt, and returns a JSON response containing a new valid bearer JWT.
6. The malicious site receives the response, including the bearer token, due to the permissive `Access-Control-Allow-Origin` header matching the localhost origin.
7. The attacker uses the intercepted bearer token to authenticate against the Vikunja API as the victim, achieving full account takeover.

## Impact

Successful exploitation results in total account compromise, granting an attacker full access to the victim's data, tasks, and administrative functions within the Vikunja instance. The impact is significant for organizations relying on Vikunja for sensitive task management, particularly where administrative or privileged user accounts are targeted via local browser-based vectors.

## Recommendation

Detection and mitigation should focus on identifying unauthorized access patterns and hardening the CORS configuration.

* Upgrade Vikunja to a version where `service.publicurl` correctly overrides default localhost origins.
* Audit web server logs for requests to `/api/v1/user/token/refresh` originating from unexpected `Origin` headers, specifically those targeting loopback IP addresses or local ports.
* Implement strict CORS policies on the reverse proxy or web server layer in front of Vikunja to explicitly whitelist only authorized production domains and strip unauthorized localhost origins from the `Access-Control-Allow-Origin` header.
