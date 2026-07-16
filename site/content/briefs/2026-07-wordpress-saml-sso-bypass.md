---
title: Authentication Bypass in miniOrange SAML SSO Login Plugin for WordPress (CVE-2026-15013)
slug: 2026-07-wordpress-saml-sso-bypass
description: A critical authentication bypass vulnerability (CVE-2026-15013) exists in the SAML Single Sign On - SSO Login plugin for WordPress, affecting all versions up to and including 5.4.3, enabling unauthenticated attackers to forge SAML assertions and achieve full administrator-level account takeover due to signature algorithm confusion.
date: "2026-07-16T05:17:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - authentication-bypass
  - saml
  - cve
vendors:
  - miniOrange
products:
  - SAML Single Sign On – SSO Login plugin for WordPress (<= 5.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1559
    technique_name: Server Software Component
    evidence: vulnerable to Authentication Bypass via SAML Signature Algorithm Confusion
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: forge a SAML assertion targeting any WordPress account — including administrators — obtain valid WordPress authentication cookies, and achieve full administrator-level account takeover
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: forge a SAML assertion targeting any WordPress account — including administrators — obtain valid WordPress authentication cookies, and achieve full administrator-level account takeover
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15013
---

A critical authentication bypass vulnerability (CVE-2026-15013) exists in the SAML Single Sign On - SSO Login plugin for WordPress, affecting all versions up to and including 5.4.3. The flaw stems from the plugin's `Mo_SAML_Utilities::mo_saml_cast_key()` function, which incorrectly reads the `SignatureMethod` Algorithm attribute directly from an attacker-controlled `SAMLResponse` parameter. This misconfiguration allows the plugin to be tricked into recasting the Identity Provider's RSA public key as an HMAC-SHA1 shared secret. Consequently, unauthenticated attackers can forge SAML assertions. Successful exploitation leads to the issuance of valid WordPress authentication cookies, enabling complete administrator-level account takeover. This vulnerability poses a significant risk to the integrity and confidentiality of affected WordPress installations, potentially allowing full control over the website and its data.

## Attack Chain

1. Attacker identifies a WordPress instance running the vulnerable SAML Single Sign On - SSO Login plugin.
2. Attacker crafts a malicious SAML assertion targeting an administrative user account.
3. The crafted assertion includes a manipulated `SignatureMethod` Algorithm attribute, specifying an HMAC-SHA1 signature method.
4. Attacker signs the crafted assertion using a forged HMAC-SHA1 signature.
5. The forged SAML assertion is sent via HTTP POST request to the vulnerable WordPress site's SAML endpoint.
6. The `Mo_SAML_Utilities::mo_saml_cast_key()` function in the plugin processes the `SAMLResponse`.
7. The plugin incorrectly reads the attacker-controlled `SignatureMethod` (HMAC-SHA1) from the `SAMLResponse` instead of enforcing the configured RSA algorithm.
8. The plugin attempts to validate the signature by recasting the legitimate Identity Provider's RSA public key as an HMAC-SHA1 shared secret, leading to successful validation of the attacker's forged signature and granting authentication as the targeted user, even an administrator.
9. Attacker obtains valid WordPress authentication cookies, achieving full administrator-level account takeover.

## Impact

Successful exploitation of CVE-2026-15013 grants unauthenticated attackers complete administrative control over the affected WordPress website. This allows for full account takeover of any user, including administrators, leading to potential data exfiltration, website defacement, arbitrary code execution via plugin/theme upload, or further compromise of the underlying server. Organizations using the affected plugin face severe risks to data integrity, confidentiality, and availability, potentially leading to significant operational disruption and reputational damage.

## Recommendation

* Patch CVE-2026-15013 immediately by updating the miniOrange SAML Single Sign On - SSO Login plugin for WordPress to a version beyond 5.4.3.
* Monitor web server logs for suspicious HTTP POST requests to your WordPress SAML SSO endpoint, especially those containing unusually large `SAMLResponse` payloads or unexpected `SignatureMethod` values.
