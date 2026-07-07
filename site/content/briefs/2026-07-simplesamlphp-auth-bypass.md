---
title: SimpleSAMLphp HTTP-Artifact Authentication Bypass via TLS Validator Confusion (CVE-2026-49283)
slug: 2026-07-simplesamlphp-auth-bypass
description: A critical vulnerability (CVE-2026-49283) in SimpleSAMLphp's HTTP-Artifact receive path allows a malicious or lower-trust Identity Provider (IdP) to bypass authentication and impersonate users from a higher-trust IdP by leveraging a flaw where `SOAPClient::validateSSL()` fails to properly validate TLS public keys for unsigned SAML Responses.
date: "2026-07-03T11:27:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - saml
  - authentication-bypass
  - identity-federation
vendors:
  - SimpleSAMLphp
products:
  - SimpleSAMLphp SAML2 (6.0.0-6.2.0)
  - SimpleSAMLphp SAML2 (5.0.0-5.0.5)
  - SimpleSAMLphp SAML2 (<4.20.2)
  - SimpleSAMLphp SAML2-Legacy (<4.20.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SimpleSAMLphp's HTTP-Artifact receive path can treat an unsigned embedded SAML `Response` as cryptographically valid for the wrong IdP, allowing a malicious or lower-trust IdP to authenticate to the SP as arbitrary users from a higher-trust victim IdP.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6929-8p9f-26jx
  - CVE-2026-49283
---

A critical vulnerability (CVE-2026-49283) in SimpleSAMLphp's HTTP-Artifact receive path allows a malicious or lower-trust Identity Provider (IdP) to bypass authentication and impersonate users from a higher-trust IdP. This flaw, present in versions < 4.20.2, >= 5.0.0 < 5.0.6, and >= 6.0.0 < 6.2.1 of the `saml2` and `saml2-legacy` packages, occurs because the `SOAPClient::validateSSL()` method fails to throw an exception when the TLS public key does not match, causing `SAML2\Message::validate()` to incorrectly deem an unsigned embedded SAML `Response` as cryptographically valid. This enables the attacker to forge assertion attributes, NameID, and session data, effectively authenticating as arbitrary users from a high-assurance IdP within a multi-IdP or federation deployment. For defenders, this means a compromised or untrusted IdP within their trust circle could gain unauthorized access to Service Providers, violating trust boundaries and leading to significant data breaches or unauthorized system access.

## Attack Chain

1.  A malicious or lower-trust Identity Provider (IdP) crafts an unsigned SAML `Response` that claims to be issued by a high-trust IdP.
2.  The malicious IdP sends an HTTP-Artifact `Response` containing this forged `SAML Response` to the Service Provider (SP).
3.  The SP's SimpleSAMLphp installation receives the HTTP-Artifact `Response` and initiates its `HTTPArtifact::receive()` processing flow.
4.  During processing of the `ArtifactResponse`, the `SOAPClient::addSSLValidator()` mechanism is invoked, providing a TLS-based validator for the outer SOAP message.
5.  The embedded unsigned SAML `Response` is then passed to `SAML2\Message::validate()`, which delegates signature validation to the validator provided by the outer `ArtifactResponse`.
6.  The `SOAPClient::validateSSL()` method, when called to validate the embedded SAML `Response`, returns normally even though the TLS public key does not match the key for the claimed high-trust IdP.
7.  Because `SOAPClient::validateSSL()` did not throw an exception, `SAML2\Message::validate()` incorrectly interprets this as successful validation, treating the unsigned embedded SAML `Response` as cryptographically valid.
8.  The SP then processes this maliciously validated SAML `Response` using metadata from the claimed high-trust IdP, granting the attacker authentication as arbitrary users from that IdP.

## Impact

This vulnerability allows a malicious or lower-trust IdP within the same SP/federation trust set to authenticate to the Service Provider (SP) as arbitrary users from any higher-trust IdP when the HTTP-Artifact binding is in use. Attackers can choose and forge assertion attributes, `NameID`, and session data within the unsigned assertion, gaining unauthorized access as legitimate users. This represents a severe authentication bypass and identity-provider impersonation issue, fundamentally undermining the security boundaries in federated environments where the integrity of different IdPs is critical. If exploited, it could lead to widespread unauthorized access, data exfiltration, or further compromise of systems relying on the affected SimpleSAMLphp instances.

## Recommendation

*   Patch CVE-2026-49283 by updating SimpleSAMLphp to a non-vulnerable version immediately:
    *   `composer/simplesamlphp/saml2`: Upgrade to `6.2.1` or later.
    *   `composer/simplesamlphp/saml2`: Upgrade to `5.0.6` or later for version 5.x branch.
    *   `composer/simplesamlphp/saml2` or `composer/simplesamlphp/saml2-legacy`: Upgrade to `4.20.2` or later for version 4.x branch.
*   Review authentication logs for unusual login patterns or failed authentications originating from specific IdPs, especially if using HTTP-Artifact binding.
