---
title: Pocket ID OIDC Refresh Token Flow Bypasses Authorization Revocation, Account Disabling, and Group Restrictions
slug: 2026-07-pocket-id-oidc-bypass
description: A vulnerability in the Pocket ID OpenID Connect (OIDC) `createTokenFromRefreshToken` function allows refresh tokens to bypass critical authorization controls, enabling threat actors to maintain perpetual access to client applications even after a user revokes authorization, an administrator disables the user account, or a user is removed from an allowed group.
date: "2026-07-28T14:14:01Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:pocket-id:pocket_id:*:*:*:*:*:*:*:*
tags:
  - oidc
  - authorization-bypass
  - persistence
  - privilege-escalation
  - identity-and-access-management
vendors:
  - Pocket ID
products:
  - pocket-id (v2.5.0)
  - pocket-id/backend (< 0.0.0-20260419162744-978ac87deffe)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: ""
    evidence: Each refresh rotates the token with a fresh 30-day expiry, enabling perpetual access after a user revokes an OIDC client's authorization, an admin disables a user account, or group restrictions are applied.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: ""
    evidence: The refresh token allows continuous access despite revocation or account disabling, effectively bypassing re-authentication or authorization checks that should have terminated access.
    confidence_band: high
cves:
  - id: CVE-2026-43983
    cvss: 8.1
    epss: 0.00247
references:
  - https://github.com/advisories/GHSA-w6p7-2fxx-4f44
---

The Pocket ID OpenID Connect (OIDC) service is affected by CVE-2026-43983, a high-severity vulnerability in the `createTokenFromRefreshToken` function (oidc_service.go:451). This flaw allows pre-existing OIDC refresh tokens to remain valid and grant access indefinitely, even if a user has revoked authorization for a client, an administrator has disabled the user's account, or the user has been removed from a group whose membership is required for client access. The vulnerability, affecting v2.5.0 and all versions with refresh token support up to HEAD (626adbf), arises because the function fails to re-validate the user's current authorization state, disabled status, or group restrictions before issuing new tokens. This bypasses critical security measures intended to terminate access, posing a significant risk of persistent unauthorized access to integrated applications and user identity data.

## Attack Chain

1. A legitimate user authorizes an OIDC client application, and Pocket ID issues an access token and a refresh token to the client.
2. Later, the user initiates an action that should revoke access, such as revoking the OIDC client's authorization, or an administrator disables the user's account in Pocket ID.
3. Alternatively, an administrator removes the user from an OIDC client's allowed user group.
4. The OIDC client (or an attacker possessing the refresh token) attempts to refresh its tokens by sending a `POST` request to `/api/oidc/token` with the refresh token.
5. The vulnerable `createTokenFromRefreshToken` function in Pocket ID processes the refresh request.
6. Due to the missing re-validation checks, the function incorrectly issues new access tokens, ID tokens, and a rotated refresh token with extended expiry, despite the user's revoked authorization, disabled account, or changed group membership.
7. The client or attacker continues to use the new tokens to access resources and retrieve user identity data (including PII from the ID token).
8. This process can be repeated, granting perpetual unauthorized access and circumventing intended security controls.

## Impact

The vulnerability has significant security implications across three key areas. Firstly, it renders user-initiated authorization revocations ineffective, allowing malicious or compromised OIDC clients to maintain indefinite access to a user's identity data, including Personally Identifiable Information (PII) such as name, email, and group memberships via the ID token. Secondly, and most critically, it completely bypasses administrative account disabling mechanisms. If an organization terminates an employee, any OIDC refresh tokens previously issued to that employee will continue to grant access to integrated services, creating a persistent backdoor. Lastly, group-based access controls for OIDC clients (e.g., "only the infrastructure team can access the CI/CD client") can be circumvented, as a user's refresh token remains valid even after they are removed from an authorized group. This undermines fine-grained access control policies and extends unauthorized access to sensitive systems integrated with Pocket ID.

## Recommendation

* Patch Pocket ID installations immediately to a version beyond `0.0.0-20260419162744-978ac87deffe` to remediate CVE-2026-43983.
* Monitor web server access logs for `POST` requests to `/api/oidc/token` originating from unusual IP addresses or user agents that are not typically associated with OIDC client applications.
* Review access logs for OIDC client applications integrated with Pocket ID, specifically looking for continued access by users whose accounts have been disabled or whose client authorizations have been revoked, as this indicates a successful bypass of security controls.
