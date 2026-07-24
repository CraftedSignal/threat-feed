---
title: Account Takeover and Stale Access via SCIM Provider-ID Collision in @better-auth/scim
slug: 2026-07-better-auth-scim-collision
description: The `@better-auth/scim` package is affected by multiple vulnerabilities, including a critical provider-ID collision flaw that allows authenticated users to craft SCIM tokens impersonating existing account providers, leading to unauthorized account access, profile modification, and user deletion, while additional issues include failed user deactivation and email update vulnerabilities bypassing uniqueness checks in versions `1.4.0-beta.27` through `1.6.21` and `1.7.0-beta.0` through `1.7.0-beta.9`.
date: "2026-07-24T15:42:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - web-application
  - account-takeover
  - sso
vendors:
  - better-auth
products:
  - '@better-auth/scim'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A low-privileged authenticated user could therefore delete users associated with a colliding provider namespace.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: A standard identity-provider deactivation signal could return success while the user kept their identity, sessions, and access.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated user could therefore mint a SCIM token whose provider ID matched an existing SSO, SAML, OIDC, generic OAuth, or social provider.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: On affected versions, `DELETE /scim/v2/Users/:id` for a non-organization SCIM token deleted the global Better Auth user and their sessions after resolving the user through the colliding provider ID.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: If the colliding provider ID matched the organization's SSO or OIDC connection, SCIM PUT or PATCH could resolve an SSO-provisioned organization member and rewrite global profile fields.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rjg6-39jm-rgg4
---

The `@better-auth/scim` plugin, utilized by applications registering it, is critically vulnerable to multiple flaws, including a provider-ID collision issue (GHSA-rjg6-39jm-rgg4). This vulnerability, affecting versions from `1.4.0-beta.27` through `1.6.21` and `1.7.0-beta.0` through `1.7.0-beta.9`, allows an authenticated attacker to craft SCIM tokens whose `providerId` matches an existing SSO, SAML, OIDC, or social provider. This enables unauthorized account access, modification of profile fields, and complete deletion of user accounts not managed by the SCIM token. Additionally, the plugin fails to correctly process `active: false` deactivation requests, potentially leaving terminated users with continued access, and bypasses email uniqueness checks during updates, leading to data corruption. These issues could lead to significant security breaches, including widespread account takeovers and denial of service for legitimate users.

## Attack Chain

1. An authenticated user accesses an application integrated with `@better-auth/scim` and generates a SCIM bearer token, leveraging either the default `canGenerateToken` policy or a custom policy vulnerable to `providerId` collision.
2. The attacker identifies a legitimate `providerId` (e.g., from an SSO, SAML, OIDC, or social provider) already in use by other account rows within the application's database.
3. The attacker crafts the SCIM bearer token or modifies its `providerId` to explicitly collide with this identified legitimate `providerId`.
4. Using this maliciously crafted SCIM token, the attacker sends a `DELETE /scim/v2/Users/:id` API request to the application, targeting a specific user ID.
5. The `@better-auth/scim` plugin, due to the `providerId` collision, incorrectly maps the request to a global user account associated with the legitimate, colliding provider, even if the SCIM token never provisioned that user.
6. The application proceeds to delete the global user and their associated sessions, leading to unauthorized account access removal and denial of service for the legitimate user.
7. Alternatively, the attacker could use `PUT` or `PATCH` requests with the crafted token to rewrite global profile fields for SSO-provisioned organization members by leveraging the `providerId` collision.
8. Further exploitation includes leveraging the absence of email uniqueness checks in `PUT` or `PATCH` updates to assign one user's email to another, potentially corrupting user login and lookup capabilities.

## Impact

The provider-ID collision issue allows an authenticated attacker to gain unauthorized access to and manipulate user accounts not under the SCIM token's legitimate scope. Attackers can delete global user records, modify profile information for SSO-provisioned organization members, and potentially corrupt email-keyed login data by reassigning email addresses without uniqueness checks. The deactivation flaw means terminated users might retain access, as the `active: false` attribute is ignored, allowing continued presence in the system even after an identity provider signals deprovisioning. These vulnerabilities pose a critical risk of widespread account takeover, denial of service, and data integrity issues for affected applications.

## Recommendation

* Immediately upgrade `@better-auth/scim` to version `1.6.22` or `1.7.0-beta.10` to address the `providerId` collision, deactivation, and email update vulnerabilities.
* If immediate upgrade is not possible, configure the `canGenerateToken` policy to explicitly reject `providerId` values that match any existing built-in, social, generic OAuth, SSO, SAML, or OIDC account provider IDs in your application.
* Restrict the generation of SCIM tokens to only trusted, privileged users to limit exposure to these vulnerabilities.
* Audit existing `scimProvider` rows in your application and remove any rows whose `providerId` matches another existing account provider namespace.
* Avoid relying solely on deactivation reports from your identity provider; manually confirm that deactivated users have lost access, particularly if your identity provider uses `active: false` for deprovisioning.
