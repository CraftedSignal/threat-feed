---
title: OneUptime SAML SSO Authentication Bypass Vulnerability (CVE-2026-34840)
slug: 2024-01-oneuptime-auth-bypass
description: OneUptime versions prior to 10.0.42 are vulnerable to an authentication bypass due to improper SAML signature validation, allowing attackers to impersonate users by prepending unsigned assertions.
date: "2026-04-02T20:16:28Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-34840
  - saml
  - authentication-bypass
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34840
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34840
rules:
  - title: Detect SAML with Multiple Assertions
    description: Detects SAML authentication requests containing multiple assertions, potentially indicating an authentication bypass attempt in OneUptime.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OneUptime Authentication Bypass Attempt via HTTP Status Code
    description: Detects potential authentication bypass attempts in OneUptime by monitoring for successful HTTP 200 responses to authentication endpoints after a SAML request with multiple assertions, indicating a bypass.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OneUptime, an open-source monitoring and observability platform, is vulnerable to an authentication bypass in versions prior to 10.0.42. The vulnerability, identified as CVE-2026-34840, resides in the SAML Single Sign-On (SSO) implementation within the `App/FeatureSet/Identity/Utils/SSO.ts` file. The flawed logic involves a decoupling of signature verification and identity extraction processes. Specifically, the `isSignatureValid()` function checks the signature of the first `<Signature>` element, while the `getEmail()` function extracts the email address from the first assertion element `assertion[0]`. This design allows an attacker to prepend a malicious, unsigned SAML assertion containing an arbitrary identity before a legitimate, signed assertion. This bypasses authentication, potentially granting unauthorized access to sensitive monitoring data and platform functionalities. The vulnerability has been patched in version 10.0.42.

## Attack Chain

1.  Attacker crafts a malicious SAML response containing an unsigned assertion with a forged identity (e.g., a privileged user's email).
2.  The attacker prepends this malicious assertion to a valid, signed SAML assertion generated for a low-privilege account or a newly created account.
3.  The combined SAML response is sent to the OneUptime platform for authentication.
4.  The `isSignatureValid()` function verifies the signature of the second assertion (the originally signed, valid one), passing the signature check.
5.  The `getEmail()` function extracts the email address from the first assertion (the malicious, unsigned one), effectively impersonating the forged identity.
6.  OneUptime grants access based on the forged identity extracted from the malicious assertion.
7.  The attacker gains unauthorized access to the OneUptime platform with the privileges of the impersonated user.
8.  The attacker can then view monitoring data, modify configurations, or perform other actions allowed to the compromised account.

## Impact

Successful exploitation of CVE-2026-34840 allows an attacker to bypass authentication and impersonate any user on the OneUptime platform. This could lead to unauthorized access to sensitive monitoring data, modification of system configurations, and potentially complete compromise of the OneUptime instance. The vulnerability has a CVSS v3.1 base score of 8.1, indicating a high severity. Organizations using vulnerable OneUptime versions are at risk of significant data breaches and operational disruption.

## Recommendation

*   Immediately upgrade OneUptime instances to version 10.0.42 or later to patch CVE-2026-34840.
*   Implement a web application firewall (WAF) rule to inspect SAML responses for multiple assertions and reject requests containing more than one assertion to prevent the attack described in the attack chain.
*   Monitor web server logs for suspicious SAML authentication requests and responses, focusing on unusual source IPs or deviations from normal authentication patterns related to the webserver log source.
