---
title: Portainer JWT Leak via URL Query Parameter
slug: 2026-05-portainer-jwt-leak
description: Portainer's authentication middleware accepts JWT bearer tokens passed as the `?token=<JWT>` URL query parameter on any authenticated API endpoint, leading to JWT leakage to logs and referrers, where a leaked token grants the full privileges of the user it was issued to, until the token expires.
date: "2026-05-14T16:37:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - jwt
  - token-leak
  - credential-access
  - CVE-2026-44883
  - portainer
vendors:
  - Portainer
products:
  - Portainer (>= 2.33.0, < 2.33.8)
  - Portainer (>= 2.39.0, < 2.39.2)
  - Portainer (>= 2.40.0, < 2.41.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-jvp4-q659-95mj
  - CVE-2026-44883
rules:
  - title: Detect Portainer JWT Parameter in Web Logs
    description: Detects Portainer JWT passed via the token query parameter in web server logs, indicating potential token leakage
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - cve-2026-44883
    techniques:
      - T1552.001
    data_sources:
      - webserver
  - title: Detect Portainer API Access Using Leaked JWT
    description: Detects Portainer API access attempts using a JWT in the Authorization header, potentially indicating use of a leaked token
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - cve-2026-44883
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 2
---

Portainer is vulnerable to JWT leakage due to accepting tokens via the `?token=<JWT>` URL query parameter. This vulnerability, present since the introduction of JWT authentication, allows the JWT to be exposed in reverse proxy logs, browser history, and HTTP Referer headers. The `?token=` parameter was used by Portainer's browser-based container attach, exec, and pod shell features, impacting any user with exec or attach rights. The issue was reported on 2026-03-06, and fixed in versions 2.33.8, 2.39.2, and 2.41.0. Exploitation requires an attacker to obtain a leaked token, but once obtained, it grants the privileges of the user it was issued to, including administrative access.

## Attack Chain

1. A user authenticates to Portainer, receiving a JWT.
2. The user initiates a container attach, exec, or pod shell operation, triggering a request to Portainer that includes the JWT as a `?token=` query parameter.
3. The request is processed by Portainer's authentication middleware, which accepts the JWT from the query parameter.
4. The request, including the JWT in the URL, is logged by a reverse proxy or other network monitoring tool.
5. Alternatively, the user navigates to an external site from within the Portainer UI, causing the JWT to be sent in the Referer header.
6. An attacker gains access to the logs or intercepts the Referer header, obtaining the leaked JWT.
7. The attacker uses the leaked JWT to authenticate to the Portainer API, impersonating the original user.
8. If the compromised token belongs to an administrator, the attacker gains full API access, including user management, container exec, and stack deployment, potentially compromising the host filesystem of managed environments.

## Impact

Successful exploitation of this vulnerability can lead to significant data breaches and system compromise. Leaked tokens can be captured by intermediate systems like reverse proxies, exposing the full JWT in plaintext. URLs containing `?token=` are recorded in browser history and forwarded in the `Referer` header. An attacker with a leaked JWT can act as the authenticated user for the remainder of the token's validity, gaining full API access, including user management, container exec, and stack deployment. If the leaked token belongs to an administrator, the attacker gains full control over Portainer and its managed environments.

## Recommendation

- Upgrade Portainer to version 2.33.8, 2.39.2, or 2.41.0 or later to remediate the vulnerability as outlined in the advisory.
- Implement reverse proxy rules to strip the `?token=` parameter from requests before they reach Portainer, as mentioned in the workarounds, but be aware this breaks container attach/exec until Portainer is patched.
- Audit existing logs for occurrences of `?token=` or `&token=` as mentioned in the workarounds, and treat any captured JWT as compromised by resetting affected user passwords.
- Deploy the Sigma rule "Detect Portainer JWT Parameter in Web Logs" to identify potential token leaks in web server logs.
- Deploy the Sigma rule "Detect Portainer API Access Using Leaked JWT" to identify API access attempts using leaked JWTs.
