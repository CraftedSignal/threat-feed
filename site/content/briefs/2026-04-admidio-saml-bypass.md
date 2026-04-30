---
title: Admidio SAML Signature Validation Bypass Allows Forged AuthnRequests and LogoutRequests
slug: 2026-04-admidio-saml-bypass
description: Admidio's SAML Identity Provider implementation fails to properly validate signatures on SAML AuthnRequests and LogoutRequests, enabling attackers to bypass signature enforcement, potentially disclose user attributes via forged SSO requests, and terminate user sessions via forged SLO requests.
date: "2026-04-29T21:56:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - saml
  - signature-bypass
  - authentication
  - authorization
  - web-application
vendors:
  - admidio
products:
  - admidio
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1495
    technique_name: Resource Hijacking
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Appliance
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Appliance
references:
  - https://github.com/advisories/GHSA-25cw-98hg-g3cg
rules:
  - title: Admidio Forged SAML AuthnRequest Detection
    description: Detects forged SAML AuthnRequests to Admidio lacking a valid signature by monitoring webserver logs for requests with a SAMLRequest parameter and specific URI.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
  - title: Admidio Forged SAML LogoutRequest Detection
    description: Detects forged SAML LogoutRequests to Admidio lacking a valid signature by monitoring webserver logs for requests with a SAMLRequest parameter and specific URI.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1495
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Admidio, a free web-based content management system for organizations and groups, contains a critical vulnerability in its SAML Single Sign-On (SSO) implementation. The `validateSignature()` method within the SAMLService class returns error strings upon signature validation failure, rather than throwing exceptions. The calling functions, `handleSSORequest()` and `handleSLORequest()`, incorrectly assume that the method throws an exception, and therefore, do not check the return value. This oversight renders the `smc_require_auth_signed` configuration option ineffective, allowing attackers to forge SAML AuthnRequests and LogoutRequests. An attacker can exploit this vulnerability to obtain sensitive user information or cause denial of service by terminating user sessions. This affects Admidio versions 5.0.8 and earlier and requires SAML SSO to be enabled.

## Attack Chain

1. An attacker crafts a malicious SAML AuthnRequest or LogoutRequest without a valid signature, impersonating a legitimate Service Provider (SP).
2. The attacker sends the forged SAML request to the Admidio instance via HTTP GET or POST to `modules/sso/index.php`.
3. The `receiveMessage()` function parses the SAML binding directly from the HTTP request, requiring no prior authentication.
4. The Entity ID is extracted from the forged request's Issuer element, and the corresponding client configuration is loaded.
5. The `validateSignature()` function is called, but its return value (indicating signature validity) is discarded.
6. For AuthnRequests, if the targeted user has an active session (`$gValidLogin` is true), the login form is skipped.
7. Admidio builds a SAML Response containing the user's attributes (login, name, email, roles) and sends it to the attacker-controlled `AssertionConsumerServiceURL`.
8. For LogoutRequests, the user's session is immediately terminated in the database, triggering a cascading single logout across all registered SPs.

## Impact

Successful exploitation of this vulnerability can lead to several critical impacts. The primary impact is the complete bypass of signature enforcement, negating the security benefits of the `smc_require_auth_signed` setting. This can lead to the disclosure of sensitive user attributes, including login name, email, and role memberships, to unauthorized parties by forging SSO requests and redirecting them to attacker-controlled endpoints. Furthermore, attackers can terminate any user's Admidio session by forging SLO requests, potentially causing a denial-of-service condition. This vulnerability affects all Admidio instances with SAML SSO enabled and can potentially impact all users of the system.

## Recommendation

*   Apply the recommended fix in the Admidio codebase to check the return value of `validateSignature()` and throw an exception on failure, as outlined in the advisory (https://github.com/advisories/GHSA-25cw-98hg-g3cg).
*   Deploy the Sigma rule "Admidio Forged SAML AuthnRequest Detection" to detect potentially malicious SAML AuthnRequests lacking a valid signature via webserver logs.
*   Deploy the Sigma rule "Admidio Forged SAML LogoutRequest Detection" to detect potentially malicious SAML LogoutRequests lacking a valid signature via webserver logs.
*   Monitor webserver logs for requests to `/adm_program/modules/sso/index.php/saml/sso` and `/adm_program/modules/sso/index.php/saml/slo` without proper signature validation to detect potential exploitation attempts.
*   Upgrade to a patched version of Admidio to address CVE-2026-41669.
