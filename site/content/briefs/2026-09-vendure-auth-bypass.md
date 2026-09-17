---
title: Account Takeover Vulnerability in Vendure External Authentication
slug: 2026-09-vendure-auth-bypass
description: Vendure is vulnerable to account takeover due to the ExternalAuthenticationService allowing unverified external identity linking to existing user accounts via email matching.
date: "2026-09-17T19:10:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vendure:vendure:*:*:*:*:*:*:*:*
tags:
  - account-takeover
  - authentication-bypass
  - web-application
vendors:
  - Vendure
products:
  - Vendure (< 3.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The flaw exists in the ExternalAuthenticationService.createCustomerAndUser() method, which links external OAuth or social login identities to pre-existing user accounts based solely on an email-address match.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The attacker's external identity is saved to the user's authentication methods, allowing for recurring unauthorized access.
    confidence_band: high
cves:
  - id: CVE-2026-63472
    cvss: 9.1
references:
  - https://github.com/advisories/GHSA-6j36-r6pr-59x4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63472
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @vendure/core to 3.7.0
      owner: IT Operations
      due: 24h
      evidence: Remediation section of GHSA-6j36-r6pr-59x4
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Vendure 3.7.0
      owner: IT Operations
      addresses: CVE-2026-63472
      evidence: Remediation note in GHSA-6j36-r6pr-59x4
---

Vendure versions prior to 3.7.0 contain a critical vulnerability in the `ExternalAuthenticationService` that enables account takeover. The flaw exists in the `createCustomerAndUser` method, which links external OAuth or SSO authentication identities to existing customer accounts based solely on an email address match. Crucially, the system does not enforce that the provided email address is verified by the external identity provider. 

In deployments using custom `AuthenticationStrategy` implementations - specifically those that fail to validate the `email_verified` claim or improperly handle unverified email addresses - an attacker can register an account on an external provider using a victim's email address. When this attacker authenticates against the vulnerable Vendure instance, the application incorrectly binds the attacker's external identity to the pre-existing account belonging to the victim. This results in the attacker gaining full access to the victim's account, including PII, order history, and the ability to perform unauthorized transactions.

## Attack Chain

1. Attacker identifies a Vendure instance configured with an external `AuthenticationStrategy` that does not enforce strict email verification.
2. Attacker creates an account on the external OIDC or OAuth provider using the target victim's email address (`victim@example.com`).
3. The external provider, not requiring rigorous verification, allows the registration.
4. Attacker initiates the authentication flow on the Vendure store using the external provider.
5. The external provider passes the email address `victim@example.com` to the Vendure `ExternalAuthenticationService`.
6. `createCustomerAndUser` identifies a pre-existing user account associated with `victim@example.com`.
7. The system silently links the attacker's `ExternalAuthenticationMethod` to the victim's account without checking the `verified` status.
8. Attacker logs in using the linked external provider and gains full access to the victim's account.

## Impact

Successful exploitation leads to full account takeover, allowing attackers to read or modify victim PII, view private order histories, update shipping addresses, and place unauthorized orders on the victim's behalf. This vulnerability affects any Vendure deployment that utilizes external authentication strategies that accept unverified email claims.

## Recommendation

1. Upgrade all Vendure instances to version 3.7.0 or later immediately to address CVE-2026-63472.
2. Audit all custom `AuthenticationStrategy` implementations to ensure they only set `verified: true` when the external identity provider has explicitly verified the email address ownership.
3. Implement logic within custom `AuthenticationStrategy` code to prevent silent linking of unverified external identities to existing accounts; require active user authentication or session verification before linking new external providers.
