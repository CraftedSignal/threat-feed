---
title: Parse Server /users/me Endpoint Exposes MFA Secrets
slug: 2024-01-30-parse-server-auth-leak
description: Parse Server versions before 8.6.61 and versions 9.0.0 to 9.6.0-alpha.55 expose sensitive MFA credentials via the `/users/me` endpoint, allowing authenticated users to extract TOTP secrets and recovery codes.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - parse-server
  - credential-access
  - mfa-bypass
vendors:
  - Parse
products:
  - Parse Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-37mj-c2wf-cx96
rules:
  - title: Detect Access to Users Me Endpoint
    description: Detects requests to the /users/me endpoint in Parse Server, which is vulnerable to MFA secret exposure.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.005
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Failed Logins Followed by /users/me Access
    description: Detects a pattern of multiple failed login attempts followed by a successful request to the /users/me endpoint, potentially indicating an attacker attempting to harvest MFA secrets after gaining initial access.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
      - T1555.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Parse Server, an open-source backend framework, contains a vulnerability in versions before 8.6.61 and versions 9.0.0 up to 9.6.0-alpha.55. The `/users/me` endpoint inadvertently exposes sensitive authentication data, including MFA TOTP secrets and recovery codes. An authenticated user possessing a valid session token can exploit this flaw. The root cause lies in the endpoint's use of master-level authentication for the session query, causing the master context to leak into user data and bypass security sanitization. This vulnerability, disclosed on March 24, 2026, as GHSA-37mj-c2wf-cx96, can lead to unauthorized access and account compromise. Defenders should prioritize patching vulnerable Parse Server instances to prevent potential credential compromise.

## Attack Chain

1. An attacker identifies a Parse Server instance running a vulnerable version (below 8.6.61 or between 9.0.0 and 9.6.0-alpha.55).
2. The attacker obtains valid user credentials through standard means (e.g., registration, password reset, or credential stuffing).
3. The attacker successfully authenticates to the Parse Server and receives a valid session token.
4. The attacker crafts a `GET` request to the `/users/me` endpoint, including the valid session token in the request headers.
5. The Parse Server processes the request, using master-level authentication for the initial session query.
6. Due to the bypassed sanitization, the response includes the targeted user's sensitive MFA TOTP secret and recovery codes.
7. The attacker uses the extracted TOTP secret to generate valid, time-based MFA codes.
8. The attacker uses the generated MFA codes, or the recovery codes, to bypass MFA and gain full access to the user's account.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass multi-factor authentication controls and gain unauthorized access to user accounts. The number of affected Parse Server instances is unknown. Impacted organizations could experience account takeovers, data breaches, and reputational damage. The severity is high due to the ease of exploitation (requires only a valid session token) and the direct exposure of MFA secrets.

## Recommendation

*   Upgrade Parse Server instances to a patched version (8.6.61 or later, or 9.6.0-alpha.55 or later) to remediate CVE-2026-33627.
*   Deploy the Sigma rule "Detect Access to Users Me Endpoint" to monitor access patterns to the vulnerable endpoint.
*   Enable detailed logging for web server requests to capture requests to the `/users/me` endpoint to facilitate investigations.
