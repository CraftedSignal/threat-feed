---
title: WordPress SAML Single Sign On Plugin Authentication Bypass (CVE-2026-15981)
slug: 2026-07-wordpress-saml-auth-bypass
description: A critical authentication bypass vulnerability, CVE-2026-15981, affects the SAML Single Sign On - SSO Login plugin for WordPress (versions up to and including 5.4.4), allowing unauthenticated attackers to log in as any existing user, including administrators, by crafting a malformed SAMLResponse that misleads the plugin's signature validation logic.
date: "2026-07-23T21:18:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - wordpress
  - web-vulnerability
  - cve-2026-15981
vendors:
  - WordPress
products:
  - SAML Single Sign On – SSO Login plugin (<= 5.4.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The SAML Single Sign On – SSO Login plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 5.4.4.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to log in as any existing WordPress user, including administrators
    confidence_band: high
cves:
  - id: CVE-2026-15981
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15981
---

The SAML Single Sign On - SSO Login plugin for WordPress, in all versions up to and including 5.4.4, is affected by a critical authentication bypass vulnerability, identified as CVE-2026-15981. This flaw, discovered and published on July 23, 2026, stems from a logical error within the `mo_saml_validate_signature()` function. Specifically, a loose boolean check incorrectly interprets an OpenSSL `openssl_verify()` error return value of `-1` as a successful signature verification. This design flaw enables unauthenticated attackers to craft specific SAMLResponse messages. By including an attacker-controlled NameID for a target user and a specially malformed signature designed to trigger the OpenSSL error, adversaries can completely bypass the authentication process, allowing them to log in as any existing WordPress user, including those with administrative privileges.

## Attack Chain

1. Attacker identifies a target WordPress instance running the vulnerable SAML Single Sign On - SSO Login plugin (versions 5.4.4 or earlier).
2. The attacker obtains or infers a valid username on the targeted WordPress site, such as an administrator account.
3. The attacker crafts a malicious SAMLResponse XML payload, including the identified target user's NameID.
4. The crafted payload deliberately includes a malformed XML digital signature value designed to cause PHP's `openssl_verify()` function to return `-1` (an error state) during signature validation.
5. The attacker sends this crafted SAMLResponse within an HTTP POST request to the WordPress site's SAML authentication endpoint.
6. The `mo_saml_validate_signature()` function within the plugin attempts to verify the signature.
7. Due to the loose boolean comparison, the function evaluates the `-1` error return from `openssl_verify()` as a 'truthy' value, mistakenly treating it as a successful signature verification.
8. The plugin proceeds to call `wp_set_auth_cookie()` for the user specified in the NameID, granting the attacker an authenticated session for the targeted WordPress account.

## Impact

A successful exploitation of CVE-2026-15981 allows an unauthenticated attacker to gain full administrative access to affected WordPress sites. This can lead to comprehensive compromise of the website, including data exfiltration, defacement, injection of malicious code, or further lateral movement within the hosting environment. Organizations utilizing the vulnerable plugin face severe risks of unauthorized access to sensitive information, disruption of services, and significant reputational damage. The critical CVSS score of 9.8 reflects the ease of exploitation and the high impact of this vulnerability.

## Recommendation

* Patch CVE-2026-15981 immediately by updating the SAML Single Sign On - SSO Login plugin for WordPress to a version greater than 5.4.4.
* Monitor webserver access logs for unusual POST requests directed at SAML authentication endpoints, especially those that might indicate attempts to bypass authentication.
