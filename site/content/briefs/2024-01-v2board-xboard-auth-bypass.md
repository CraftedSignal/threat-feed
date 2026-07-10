---
title: V2Board and Xboard Authentication Bypass via Exposed Tokens
slug: 2024-01-v2board-xboard-auth-bypass
description: V2Board and Xboard are vulnerable to authentication bypass due to exposing authentication tokens in HTTP response bodies, allowing unauthenticated attackers to gain complete account access.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-39912
  - v2board
  - xboard
  - authentication-bypass
  - webserver
vendors:
  - V2Board
  - Xboard
products:
  - V2Board
  - Xboard
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39912
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39912
rules:
  - title: Detect V2Board/Xboard loginWithMailLink Request
    description: Detects requests to the loginWithMailLink endpoint, which is vulnerable to authentication token exposure.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect V2Board/Xboard token2Login Request
    description: Detects requests to the token2Login endpoint, used to exchange tokens for bearer tokens.
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

V2Board versions 1.6.1 through 1.7.4 and Xboard versions through 0.1.9 are vulnerable to an authentication bypass vulnerability, tracked as CVE-2026-39912. This vulnerability exists in the `loginWithMailLink` endpoint when the `login_with_mail_link_enable` feature is active. An unauthenticated attacker can exploit this vulnerability by sending a POST request to the `loginWithMailLink` endpoint with a known email address. The server responds with a full authentication URL containing a token, which can then be exchanged at the `token2Login` endpoint to obtain a valid bearer token, granting the attacker complete account access, potentially including administrative privileges. This allows for a complete account takeover without any prior authentication.

## Attack Chain

1. The attacker identifies a target V2Board or Xboard instance running a vulnerable version (V2Board 1.6.1-1.7.4 or Xboard <= 0.1.9) with the `login_with_mail_link_enable` feature enabled.
2. The attacker identifies a valid email address associated with an account on the target V2Board/Xboard instance.
3. The attacker sends an unauthenticated POST request to the `/loginWithMailLink` endpoint, including the target email address in the request body.
4. The server responds with an HTTP response body containing a URL that includes an authentication token (e.g., `https://example.com/auth?token=YOUR_TOKEN`).
5. The attacker extracts the authentication token from the URL provided in the response.
6. The attacker sends a request (likely POST) to the `/token2Login` endpoint, providing the extracted authentication token in the request body.
7. The server validates the token and responds with a valid bearer token.
8. The attacker uses the acquired bearer token to authenticate to the application and gain complete account access, potentially including administrative privileges, allowing them to modify settings, access sensitive data, and perform unauthorized actions.

## Impact

Successful exploitation of CVE-2026-39912 allows an unauthenticated attacker to gain complete control of user accounts on affected V2Board and Xboard instances. This can lead to data breaches, service disruption, and unauthorized modifications to the platform. Given that V2Board and Xboard are often used for subscription management and content delivery, a successful attack could compromise sensitive user data, including payment information and personal details. The vulnerability has a CVSS v3.1 base score of 9.1, indicating its critical severity.

## Recommendation

*   Disable the `login_with_mail_link_enable` feature immediately as a temporary mitigation.
*   Upgrade V2Board to a version later than 1.7.4 or Xboard to a version later than 0.1.9 to patch CVE-2026-39912.
*   Deploy the Sigma rule "Detect V2Board/Xboard loginWithMailLink Request" to monitor for suspicious requests to the `/loginWithMailLink` endpoint.
*   Deploy the Sigma rule "Detect V2Board/Xboard token2Login Request" to monitor for suspicious requests to the `/token2Login` endpoint.
