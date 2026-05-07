---
title: Ech0 'Never Expire' Access Tokens Cannot Be Revoked
slug: 2024-04-29-ech0-token-revocation
description: Ech0's access tokens with the 'never expire' option cannot be revoked through logout or deletion, leading to persistent access until the JWT secret is rotated instance-wide.
date: "2026-05-07T21:34:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - token-revocation
  - web-application
vendors:
  - lin-snow
products:
  - Ech0
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1587
    technique_name: Develop Capabilities
references:
  - https://github.com/advisories/GHSA-fpw6-hrg5-q5x5
rules:
  - title: Detect Ech0 API Logout Panic Due to Missing Expiration
    description: Detects HTTP 500 errors on the /api/auth/logout endpoint, indicating a potential panic due to a missing expiration claim in a 'never expire' token.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1587.001
    data_sources:
      - webserver
  - title: Detect Ech0 API Access Token Deletion Without JTI Blacklisting
    description: Detects attempts to delete access tokens via the API endpoint without subsequent revocation, potentially indicating a failure in JTI blacklisting.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1587.001
    data_sources:
      - webserver
rules_count: 2
---

Ech0, a self-hosted platform, has a vulnerability concerning the revocation of access tokens created with the "never expire" option. These tokens, lacking an `exp` (expiration) claim, bypass three revocation mechanisms. Specifically, the logout function panics when attempting to process these tokens due to a nil pointer dereference, while the admin's "Delete token" function removes the database record without blacklisting the JTI (JWT ID). This means that if a "never expire" token is compromised, it remains valid until the `JWT_SECRET` is rotated, an action that affects all users on the platform. This issue was found by aisage.io. Version 4.5.6 is affected.

## Attack Chain

1. An administrator creates an access token with the "never expire" option. This token lacks the `exp` claim in its JWT.
2. The attacker obtains a "never expire" token through theft or compromise (e.g., stolen laptop, exposed configuration file).
3. The attacker uses the stolen token in an HTTP Authorization header to access protected resources. The middleware accepts the token since it has a valid signature.
4. The legitimate owner attempts to revoke the token via logout. The logout handler attempts to parse the token and extract the expiration time.
5. Parsing of the token in the logout handler leads to a panic because it attempts to access `.Time` field of a nil `ExpiresAt` claim (present only on tokens with expiry). The token revocation is skipped.
6. The administrator attempts to delete the access token via the admin panel. This action removes the metadata for the token from the database, but does not blacklist the JTI.
7. The attacker continues to use the token for authorized requests, bypassing revocation attempts.
8. The attacker maintains perpetual access to the system, leveraging the scopes associated with the stolen token.

## Impact

Compromised "never expire" tokens grant attackers persistent authenticated access to Ech0 instances. This access remains valid until the `JWT_SECRET` is rotated, forcing a platform-wide reset. Administrators are misled by the "Delete token" function, which appears to revoke access but does not. The need to rotate the `JWT_SECRET` for proper revocation introduces a blast radius, requiring every user to log in again.

## Recommendation

- Replace "never expire" tokens with very long-lived tokens, ensuring an `exp` claim exists. See code example in the overview section.
- Modify the logout handler to gracefully handle tokens with a nil `ExpiresAt` field. See code example in the overview section.
- When deleting an access token through the admin panel, blacklist the corresponding JTI. See code example in the overview section.
- Rotate the JWT secret immediately if a "never expire" token is suspected of being compromised. This invalidates all active tokens and prevents further unauthorized access.
