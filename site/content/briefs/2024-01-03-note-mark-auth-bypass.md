---
title: Note Mark OIDC Authentication Bypass via Hardcoded Password
slug: 2024-01-03-note-mark-auth-bypass
description: A critical authentication bypass vulnerability in note-mark allows attackers to authenticate as any OIDC-registered user by submitting the password 'null' to the internal login endpoint due to a hardcoded bcrypt hash fallback, potentially leading to account takeover and persistent access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - credential-access
  - note-mark
  - ghsa
products:
  - note-mark
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-pxf8-6wqm-r6hh
rules:
  - title: Detect Note Mark Authentication Bypass Attempt
    description: Detects attempts to exploit the note-mark authentication bypass vulnerability by monitoring for POST requests to the /api/auth/token endpoint with a 'password' field set to 'null'.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
  - title: Detect Note Mark Password Change with Null Existing Password
    description: Detects attempts to change a user's password in Note Mark using the 'null' password bypass via the `/api/users/me/password` endpoint.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical authentication bypass vulnerability affects note-mark deployments configured with OIDC authentication. The vulnerability stems from the `IsPasswordMatch` function in `backend/db/models.go`, which falls back to a hardcoded `bcrypt("null")` hash when a user has no stored password. This occurs because OIDC-registered users are created with an empty password. As a result, any attacker can authenticate as an OIDC user by submitting the password "null" to the internal login endpoint (`POST /api/auth/token`). This issue affects note-mark version 0.19.2 and potentially earlier versions. The default configuration ships with both authentication paths side-by-side, so any site that turns on OIDC is affected, allowing for potential account takeover and data exfiltration.

## Attack Chain

1. An attacker identifies a note-mark instance with OIDC enabled and internal login enabled (default configuration). The attacker can confirm this by accessing `/api/info`.
2. The attacker enumerates valid usernames via the `/api/users/search` endpoint (anonymous user search enabled by default).
3. The attacker sends a POST request to `/api/auth/token` with the target username and password "null".
4. The `IsPasswordMatch` function in `backend/db/models.go` is called. Since OIDC-registered users have an empty password, the function uses the `nullPasswordHash`.
5. The `bcrypt.CompareHashAndPassword` function compares `nullPasswordHash` with the provided password "null", resulting in a successful match.
6. The server issues an `Auth-Session-Token` cookie to the attacker.
7. The attacker uses the valid session cookie to access the target user's account via `/api/users/me` or other authenticated endpoints.
8. The attacker persists access by updating the target user's password via `PUT /api/users/me/password` using "null" as the existing password, locking out the legitimate user and gaining persistent access.

## Impact

Successful exploitation of this vulnerability allows an attacker to fully take over OIDC-only user accounts on affected note-mark deployments. This includes reading private notebooks, note markdown, and uploaded assets. An attacker can also write, edit, or delete anything the compromised user owns, leading to significant data loss and confidentiality breaches. The vulnerability is especially severe due to the default configuration enabling both OIDC and internal login paths, making it easy for attackers to exploit.

## Recommendation

*   Apply the recommended fix by rejecting the login path for users with no stored password in `backend/services/auth.go` and `backend/services/users.go` as detailed in the advisory. This directly addresses the vulnerability by preventing authentication with the "null" password.
*   Monitor network traffic for POST requests to `/api/auth/token` with a request body containing `"password":"null"` to identify potential exploitation attempts using the provided Sigma rule.
*   Consider disabling internal logins (`EnableInternalLogin`) if OIDC is the sole authentication method used, mitigating the risk by removing the vulnerable login path.
