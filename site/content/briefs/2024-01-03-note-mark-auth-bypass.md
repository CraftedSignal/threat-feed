---
title: Note Mark OIDC Authentication Bypass via Hardcoded Password
slug: 2024-01-03-note-mark-auth-bypass
description: A critical authentication bypass vulnerability in note-mark allows attackers to authenticate as any OIDC-registered user by submitting the password 'null' to the internal login endpoint due to a hardcoded bcrypt hash fallback, potentially leading to account takeover and persistent access.
date: "2024-01-03T12:00:00Z"
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

A critical authentication bypass vulnerability affects note-mark deployments configured with OIDC authentication. The vulnerability stems from the `IsPasswordMatch` function in `backend/db/models.go`, which falls back to a hardcoded `bcrypt("null")` hash when a user has no stored password. This occurs because OIDC-registered users are created with an empty password. As a result, any attacker can authenticate as an OIDC user by submitting the password "null" to the internal login endpoint (`POST…
