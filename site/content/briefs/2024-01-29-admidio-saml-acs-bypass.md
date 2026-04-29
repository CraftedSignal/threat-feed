---
title: Admidio SAML Assertion Consumer Service (ACS) URL Validation Bypass
slug: 2024-01-29-admidio-saml-acs-bypass
description: Admidio's SAML IdP implementation in its SSO module is vulnerable to sending SAML responses to unvalidated Assertion Consumer Service URLs, allowing an attacker to craft a SAML AuthnRequest with an arbitrary AssertionConsumerServiceURL, causing the IdP to send the signed SAML response, containing user identity attributes, to an attacker-controlled URL, enabling impersonation of the victim user on the legitimate SP by replaying the SAML assertion.
date: "2024-01-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - saml
  - sso
  - acs-bypass
  - admidio
  - cve-2026-41670
vendors:
  - admidio
products:
  - admidio
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-p9w9-87c8-m235
iocs:
  - type: url
    value: https://attacker.test/steal-saml
  - type: url
    value: https://legitimate-sp.test/metadata
ioc_counts:
  url: 2
rules:
  - title: Admidio SAML AuthnRequest ACS URL Override
    description: Detects SAML AuthnRequests with a suspicious AssertionConsumerServiceURL parameter, indicating a potential ACS URL override attempt in Admidio.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connection to SAML Stealing Server
    description: Detects network connections to attacker-controlled domains used to steal SAML assertions.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - credential_access
    techniques:
      - T1071.001
      - T1550.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability exists in Admidio's SAML IdP implementation within the SSO module (versions 5.0.8 and earlier) that allows for bypassing Assertion Consumer Service (ACS) URL validation. The IdP uses the `AssertionConsumerServiceURL` value directly from incoming SAML AuthnRequest messages as the destination for the SAML response without verifying it against the registered `smc_acs_url` for the corresponding service provider client. An attacker can exploit this by crafting a SAML AuthnRequest with the Entity ID of a registered SP client and an attacker-controlled `AssertionConsumerServiceURL`. This causes the IdP to send the signed SAML response, containing sensitive user identity attributes (login name, email, roles, profile fields), to a URL controlled by the attacker. The default configuration does not require signed AuthnRequests, simplifying exploitation to only needing the SP's Entity ID.

## Attack Chain

1.  The attacker identifies the Entity ID of a registered SAML service provider (SP) client within the Admidio IdP. This is often publicly available from the SP's metadata endpoint.
2.  The attacker crafts a malicious SAML AuthnRequest. The AuthnRequest includes the legitimate SP Entity ID as the Issuer, but sets the `AssertionConsumerServiceURL` to a URL controlled by the attacker (e.g., `https://attacker.test/steal-saml`).
3.  The attacker sends the crafted SAML AuthnRequest to Admidio's SSO endpoint (`/modules/sso/index.php/saml/sso`) using the HTTP-POST binding, typically by tricking a logged-in user into accessing a webpage containing an auto-submitting form.
4.  Admidio's SSO module receives the AuthnRequest. If signature validation is not enforced for the SP, the request proceeds without signature verification.
5.  If the user is already authenticated with the Admidio IdP, the IdP generates a signed SAML response containing the user's identity and attributes. The destination of the SAML response is set to the attacker-controlled `AssertionConsumerServiceURL` taken directly from the AuthnRequest.
6.  Admidio renders an auto-submitting HTML form in the victim's browser, which POSTs the signed SAML response to the attacker's URL (`https://attacker.test/steal-saml`).
7.  The attacker's server receives the SAML response, extracting the user's login name, email, full name, roles, and any other profile fields included in the assertion.
8.  The attacker replays the stolen SAML assertion to the legitimate SP to authenticate as the victim, gaining unauthorized access to the SP application and its resources.

## Impact

Successful exploitation of this vulnerability allows an attacker to steal user identities and impersonate victims on legitimate service provider applications. This leads to unauthorized access to user accounts and potential access to sensitive data and resources within those applications. The scope change enables impersonation across separate service provider applications. The vulnerability is exploitable without requiring knowledge of cryptographic keys if `smc_require_auth_signed` is not enabled, making it easier to exploit. All versions of Admidio up to and including 5.0.8 are affected.

## Recommendation

*   Apply the vendor-supplied patch described in GHSA-p9w9-87c8-m235 by upgrading to a version of Admidio greater than 5.0.8.
*   As a temporary mitigation, enable `smc_require_auth_signed` and `smc_validate_signatures` for all SAML clients to enforce signature validation, mitigating attacks from unauthenticated sources.
*   Monitor web server logs for POST requests to the Admidio SSO endpoint (`/modules/sso/index.php/saml/sso`) with suspicious `SAMLRequest` parameters containing attacker-controlled `AssertionConsumerServiceURL` values, which can be detected using the "Admidio SAML AuthnRequest ACS URL Override" Sigma rule.
*   Monitor network traffic for connections to attacker-controlled URLs, such as `https://attacker.test/steal-saml`, which may indicate successful exploitation and the exfiltration of SAML responses as listed in the IOC table.
