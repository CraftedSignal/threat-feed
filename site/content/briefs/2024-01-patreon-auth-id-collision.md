---
title: Patreon OAuth Provider ID Collision Vulnerability in go-pkgz/auth
slug: 2024-01-patreon-auth-id-collision
description: The Patreon OAuth provider in go-pkgz/auth and go-pkgz/auth/v2 maps every authenticated Patreon account to the same local user ID, leading to cross-account access, privilege confusion, and subscription-state leakage.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication
  - oauth
  - id_collision
  - vulnerability
vendors:
  - GitHub
products:
  - auth
  - auth/v2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-f6qq-3m3h-4g42
rules:
  - title: Patreon Auth ID Collision Attempt
    description: Detects attempts to exploit the Patreon Auth ID collision vulnerability by monitoring for the specific user ID pattern.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
      - linux
  - title: Patreon Auth v2 ID Collision Attempt
    description: Detects attempts to exploit the Patreon Auth ID collision vulnerability in v2 by monitoring for the specific user ID pattern in access logs.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists in the Patreon OAuth provider within the `go-pkgz/auth` and `go-pkgz/auth/v2` libraries. Specifically, the `mapUser` function incorrectly maps all authenticated Patreon accounts to the same local `user.ID`, instead of generating unique IDs based on the Patreon account data. This flaw, present in versions 1.18.0 through 1.25.1 of `go-pkgz/auth` and 2.0.0 through 2.1.1 of `go-pkgz/auth/v2`, arises because the code hashes an uninitialized field instead of the Patreon user ID. This means that all Patreon users are effectively treated as a single identity within applications using these libraries. The vulnerability poses a significant risk to applications relying on `token.User.ID` for authentication and authorization decisions.

## Attack Chain

1. A user attempts to authenticate with an application using the affected `go-pkgz/auth` library and the Patreon OAuth provider.
2. The application redirects the user to Patreon for authentication.
3. The user authenticates with Patreon and is redirected back to the application with an authorization code.
4. The application exchanges the authorization code for an access token.
5. The application uses the access token to retrieve the user's Patreon profile data.
6. The application calls the vulnerable `mapUser` function within the `go-pkgz/auth` library to map the Patreon user to a local user. Due to the vulnerability, all users are mapped to the same local user ID: `patreon_da39a3ee5e6b4b0d3255bfef95601890afd80709`.
7. The application stores the mapped user object in JWT claims.
8. Subsequent requests from different Patreon users are treated as coming from the same user, potentially leading to data leakage, privilege escalation, or account takeover.

## Impact

This vulnerability can lead to severe consequences for applications using the affected libraries. If successful, all Patreon-authenticated users may be collapsed into a single local account. This can result in data associated with one Patreon user being exposed to or overwritten by another. Additionally, Patreon-specific attributes like subscription status can leak across unrelated users. If the application grants elevated privileges to the local account associated with the shared Patreon ID, those privileges can effectively apply to every Patreon login.

## Recommendation

*   Upgrade `go-pkgz/auth` to a version higher than 1.25.1 or `go-pkgz/auth/v2` to a version higher than 2.1.1 to patch CVE-2026-42560.
*   Review and update any existing applications using the vulnerable Patreon provider to ensure proper user ID mapping after patching CVE-2026-42560.
*   Deploy the Sigma rule "Patreon Auth ID Collision Attempt" to detect potential exploitation by monitoring for the specific user ID pattern `patreon_da39a3ee5e6b4b0d3255bfef95601890afd80709` in authentication logs.
*   Implement additional logging and monitoring to track user authentication events and identify any anomalies in user ID assignments.
