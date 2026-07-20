---
title: '@better-auth/sso Authorization Bypass Allows Unauthorized SSO Provider Registration'
slug: 2026-07-better-auth-sso-auth-bypass
description: A high-severity authorization bypass vulnerability (CVE-2026-53515) in `@better-auth/sso` versions `>= 1.2.10, < 1.6.11` allows regular organization members to register new SSO providers for an organization, potentially leading to unauthorized user creation and, under specific configurations, unauthorized administrative access within the target organization.
date: "2026-07-20T21:10:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web
  - vulnerability
  - authorization-bypass
  - sso
vendors:
  - Better Auth
products:
  - '@better-auth/sso (>= 1.2.10, < 1.6.11)'
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: a regular member can attach an attacker-controlled OIDC or SAML identity provider to an organization they do not administer. After registration, downstream organization provisioning can add IdP-asserted users from `/sso/callback/{providerId}` into the target organization
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Forge Web Credentials
    evidence: if `organizationProvisioning.defaultRole` or `organizationProvisioning.getRole` returns `admin` or higher for SSO-provisioned users. The bug then becomes unauthorized admin creation in the org.
    confidence_band: high
cves:
  - id: CVE-2026-53515
    cvss: 7.1
    epss: 0.00242
references:
  - https://github.com/advisories/GHSA-gv74-j8m3-fg5f
---

A critical authorization bypass vulnerability, tracked as CVE-2026-53515, has been identified in the `@better-auth/sso` package, affecting versions `>= 1.2.10` and `< 1.6.11`. This flaw allows any member of an organization to register a new Single Sign-On (SSO) provider via the `POST /sso/register` endpoint, even if they lack administrative privileges. The vulnerability arises because the endpoint checks for a valid membership but fails to verify the user's administrative role, a check that is enforced for other SSO provider management actions like listing, getting, updating, or deleting. This authorization mismatch enables unauthorized configuration of SSO providers and can lead to the creation of unapproved user accounts, and potentially administrative accounts, within the affected organization, especially if `organizationProvisioning.defaultRole` is set to 'admin' or `domainVerification.enabled` is false. Organizations leveraging `sso()` and `organization()` plugins with a non-zero `providersLimit` are particularly at risk.

## Attack Chain

1. An attacker obtains or utilizes an existing regular member account within a target organization that uses `@better-auth/sso`.
2. The attacker crafts and sends an HTTP POST request to the `/sso/register` endpoint, including details for a new, attacker-controlled OIDC or SAML identity provider, specifying the target `organizationId`.
3. Due to the authorization bypass (CVE-2026-53515), the `@better-auth/sso` application successfully processes the registration without verifying the caller's administrative role.
4. A new, attacker-controlled SSO provider is created and illicitly associated with the target organization.
5. The attacker then directs users (or themselves) to authenticate via this newly registered SSO provider, which processes identities through the `/sso/callback/{providerId}` endpoint.
6. The application's `organizationProvisioning` mechanism adds these IdP-asserted users into the target organization.
7. If the `organizationProvisioning.defaultRole` or `organizationProvisioning.getRole` is configured to return `admin` for provisioned users, the attacker can create new administrative accounts.
8. The final objective is unauthorized control over SSO configurations, unauthorized user creation, or potentially unauthorized administrative access within the target organization.

## Impact

This vulnerability can lead to several severe consequences for affected organizations. The primary impact is the unauthorized configuration of SSO providers, allowing a low-privileged member to link an attacker-controlled identity provider to the organization. This can further lead to unauthorized organization membership creation, where IdP-asserted users are added to the target organization without proper oversight. In the worst-case scenario, if `organizationProvisioning.defaultRole` is set to `admin` or `organizationProvisioning.getRole` returns `admin`, the issue can result in the creation of administrative-level accounts within the organization without owner consent, effectively granting an attacker broad control. The immediate usability of a malicious provider is heightened if `domainVerification.enabled` is `false`.

## Recommendation

* **Patch CVE-2026-53515 immediately** by upgrading to `@better-auth/sso@1.6.11` or later to ensure the `registerSSOProvider` handler enforces the correct administrative role check.
* **Disable user-driven SSO registration** by setting `sso({ providersLimit: 0 })` if immediate upgrade is not possible. This will prevent all self-serve provider creation, requiring server-side calls for legitimate registrations.
* **Disable SSO-driven organization provisioning** by setting `sso({ organizationProvisioning: { disabled: true } })` if direct upgrade is unfeasible, which will prevent the malicious provider from automatically adding users.
* **Implement a custom `before` hook** on `/sso/register` that explicitly asserts the caller's role on `body.organizationId` is `owner` or `admin` as a temporary workaround until patching is complete.
* **Audit existing `ssoProvider` rows** where `organizationId IS NOT NULL` and cross-reference the `userId` with `member.role` to identify and remove provider records created by non-admin users.
