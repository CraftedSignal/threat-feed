---
title: Authorization Bypass in @better-auth/scim Plugin
slug: 2026-08-better-auth-scim-auth-bypass
description: An authorization bypass vulnerability in @better-auth/scim allows authenticated users to mint tokens that collide with provider IDs, enabling unauthorized modification and takeover of global user accounts.
date: "2026-08-01T13:51:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - scim
  - identity-management
  - cve-2026-67330
vendors:
  - Better Auth
products:
  - '@better-auth/scim'
cves:
  - id: CVE-2026-67330
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67330
---

The @better-auth/scim plugin is susceptible to an authorization bypass vulnerability identified as CVE-2026-67330, affecting versions 1.4.0-beta.27 through 1.6.21 and 1.7.0-beta.0 through 1.7.0-beta.9. The flaw resides in the SCIM token issuance logic, which fails to restrict provider IDs to those uniquely belonging to the SCIM configuration. 

Because the system uses the same logical provider ID for both SCIM configuration and account ownership, an authenticated user can craft a SCIM token with a provider ID that matches an existing SSO, SAML, OIDC, or social account provider. When this malicious token is used, the system incorrectly resolves the request to account rows that were not provisioned by that specific SCIM token. This allows an attacker to interact with global user accounts and sessions belonging to other providers, facilitating profile and email manipulation without uniqueness checks, unauthorized data exfiltration, and account takeover. The vulnerability is resolved in versions 1.6.22 and 1.7.0-beta.10.

## Impact

The vulnerability poses a severe risk of account takeover and unauthorized administrative control over user sessions. By manipulating global user profile fields and email addresses, an attacker can hijack accounts or delete them entirely, causing significant service disruption and loss of confidentiality for all identity providers integrated through the affected @better-auth/scim plugin.

## Recommendation

- Upgrade the @better-auth/scim plugin to version 1.6.22 or 1.7.0-beta.10 immediately to remediate CVE-2026-67330.
- Audit application logs for abnormal SCIM administrative activity or mass profile modification events associated with non-standard provider ID patterns.
- Review all existing SCIM token configurations to ensure provider ID namespaces are not colliding with other established SSO or OIDC providers.
