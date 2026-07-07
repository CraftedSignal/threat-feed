---
title: SimpleSAMLphp SP IdP Bypass Vulnerability (CVE-2026-49284)
slug: 2026-07-simplesamlphp-idp-bypass
description: SimpleSAMLphp's Service Provider (SP) does not properly enforce the expected Identity Provider (IdP) for an SP-initiated login when a response from a different IdP is received, allowing an attacker to exploit CVE-2026-49284 in multi-IdP deployments to bypass authentication and authorization controls by substituting a lower-trust IdP's response for a higher-trust one, potentially gaining unauthorized access or elevating privileges if application authorization relies on the specific IdP used.
date: "2026-07-03T11:11:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - saml
  - vulnerability
  - web-application
  - authentication-bypass
  - authorization-bypass
vendors:
  - SimpleSAMLphp
products:
  - simplesamlphp (>= 2.5.0, <= 2.5.1)
  - simplesamlphp (<= 2.4.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SimpleSAMLphp's SAML SP ACS path does not enforce the IdP selected for an SP-initiated login. If a saved SP state contains `ExpectedIssuer = IdP A`, but the ACS receives a valid response from `IdP B`, the code logs a warning and continues processing instead of rejecting the response.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: In a multi-IdP deployment, a lower-trust IdP can satisfy SP state created for a different expected IdP. ... In those deployments this is an authentication/authorization bypass candidate.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The impact is highest when the SP trusts multiple IdPs with different assurance levels... and application authorization depends on the selected/expected IdP. In those deployments this is an authentication/authorization bypass candidate.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-q8r6-xj3f-wrrm
---

A vulnerability (CVE-2026-49284) has been identified in SimpleSAMLphp affecting versions up to 2.4.6 and between 2.5.0 and 2.5.1. This flaw stems from the Service Provider (SP) failing to enforce the intended Identity Provider (IdP) during an SP-initiated login, particularly in multi-IdP environments. Specifically, if a saved SP state expects a response from IdP A, but the Assertion Consumer Service (ACS) receives a valid SAML response from a different IdP (IdP B), SimpleSAMLphp logs a warning but proceeds to process the response. This behavior is critical when combined with the SP's handling of unsigned `samlp:Response/@InResponseTo` elements outside of signed assertions, especially if the signed assertion's `SubjectConfirmationData` lacks its own `InResponseTo`. This combination allows an attacker to bind a response from a trusted, but potentially lower-trust, IdP to SP state originally created for a higher-trust IdP, leading to authentication and authorization bypasses.

## Attack Chain

1.  **Initial Access / User Impersonation:** A legitimate user initiates an SP-initiated SAML login request to a SimpleSAMLphp SP, which expects authentication from a specific high-trust IdP (IdP A).
2.  **Attacker Intercepts/Manipulates Flow:** An attacker manipulates the SAML exchange, potentially redirecting the user or crafting a SAML response from a trusted, but lower-assurance, IdP (IdP B) that the SP also trusts.
3.  **Crafted SAML Response:** The attacker generates a SAML response from IdP B. This response contains a valid, signed assertion but deliberately omits the `InResponseTo` attribute within `SubjectConfirmationData`.
4.  **Unsigned Response-Level `InResponseTo`:** The attacker also includes an unsigned `samlp:Response/@InResponseTo` attribute in the overall SAML response, which matches the expected value from the SP-initiated request.
5.  **SimpleSAMLphp Processing Flaw:** The SimpleSAMLphp SP receives this crafted SAML response. Despite the `ExpectedIssuer` in its saved state pointing to IdP A, it processes the response from IdP B because the assertion is validly signed and the `InResponseTo` checks are bypassed by the combination of missing `SubjectConfirmationData/InResponseTo` and unsigned `Response/InResponseTo`.
6.  **IdP Mismatch Ignored:** The SP issues a warning about the IdP mismatch but continues processing, accepting the authentication from IdP B.
7.  **Authentication/Authorization Bypass:** The user is authenticated by the SP as if they had logged in via IdP A, potentially bypassing intended authorization checks or gaining access with different trust levels than expected.
8.  **Unauthorized Access / Privilege Escalation:** If the application's authorization relies on the specific IdP used for login or its associated trust level, the attacker achieves unauthorized access or privilege escalation within the application.

## Impact

This vulnerability significantly impacts deployments where SimpleSAMLphp functions as a Service Provider (SP) and trusts multiple Identity Providers (IdPs) with varying levels of assurance, different tenant boundaries, or distinct attribute namespaces. The primary consequence is an authentication and authorization bypass, enabling a lower-trust IdP to satisfy SP state created for a higher-trust or specific expected IdP. This can subvert security mechanisms designed to route users to particular IdPs, including configurations with `enable_unsolicited` set to `false`. Attackers could gain unauthorized access or escalate privileges within the application if authorization decisions are tied to the selected IdP or its trust context. The severity of the impact is contingent on the attacker's ability to obtain signed IdP-initiated assertions from a trusted, but less secure, IdP and how application authorization maps user identifiers.

## Recommendation

*   Upgrade SimpleSAMLphp to a patched version immediately to remediate `CVE-2026-49284`.
*   Review your SimpleSAMLphp `sp-remote` configurations for any multi-IdP deployments that might be affected by `CVE-2026-49284`.
