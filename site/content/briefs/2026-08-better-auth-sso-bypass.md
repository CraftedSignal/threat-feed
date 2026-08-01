---
title: Authentication Bypass in @better-auth/sso
slug: 2026-08-better-auth-sso-bypass
description: Multiple authentication bypass vulnerabilities in @better-auth/sso allow attackers to perform account takeovers by exploiting flaws in SSO provider handling.
date: "2026-08-01T13:53:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - sso
  - account-takeover
  - cve-2026-67328
vendors:
  - better-auth
products:
  - sso
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Attackers can exploit domain verification parsing mismatches, orphaned provider accounts, unbound SAML assertions, or reflected XSS on logout endpoints to gain unauthorized session access and account takeover.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550.001
    technique_name: 'Use Alternate Authentication Material: Application Access Token'
    evidence: Attackers can exploit ... unbound SAML assertions ... to gain unauthorized session access and account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-67328
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67328
  - https://github.com/better-auth/better-auth/security/advisories/GHSA-prpr-5gj3-qqhg
  - https://www.vulncheck.com/advisories/better-auth-sso-before-account-takeover-via-sso
---

The @better-auth/sso library is affected by multiple authentication bypass vulnerabilities in versions prior to 1.6.21 and specific beta versions (1.7.0-beta.0 through 1.7.0-beta.9). These flaws exist within the SSO provider handling logic, enabling attackers to sign in as arbitrary users. The vulnerabilities stem from disparate issues including domain verification parsing mismatches, improper handling of orphaned provider accounts, unbound SAML assertions, and reflected Cross-Site Scripting (XSS) on logout endpoints. By leveraging these weaknesses, an attacker can manipulate the authentication flow to gain unauthorized session access and execute full account takeover. Given the library's role in facilitating SSO integrations, these vulnerabilities pose a significant risk of unauthorized access to enterprise applications and user data.

## Attack Chain

1. The attacker identifies an application utilizing a vulnerable version of @better-auth/sso.
2. The attacker initiates an authentication request to the SSO provider.
3. The attacker intercepts or modifies the response, exploiting domain verification parsing mismatches or injecting an unbound SAML assertion.
4. Alternatively, the attacker triggers a reflected XSS on the logout endpoint to steal session identifiers or manipulate session state.
5. The @better-auth/sso library incorrectly validates the forged or manipulated SSO assertion.
6. The application grants the attacker an authenticated session associated with the target user's identity.
7. The attacker accesses the application as the target user, achieving unauthorized access or complete account takeover.

## Impact

Successful exploitation leads to unauthorized access to user accounts, enabling attackers to view private data, perform unauthorized actions on behalf of users, or elevate privileges if the account is an administrator. This impacts all applications and services that rely on the @better-auth/sso library for authentication, potentially exposing thousands of user sessions depending on the scale of the deployment.

## Recommendation

Prioritized actions for development and security teams:
- Upgrade @better-auth/sso to version 1.6.21 or 1.7.0-beta.10 immediately to remediate the vulnerabilities.
- Review authentication logs for unusual session activity or authentication requests originating from unexpected SSO providers.
- Audit custom authentication logic that integrates with @better-auth/sso to ensure strict validation of SAML assertions and SSO responses.
- Implement monitoring for XSS patterns on logout endpoints as a compensatory measure while patching.
