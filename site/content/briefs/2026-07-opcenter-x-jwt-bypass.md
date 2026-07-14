---
title: Critical JWT Authentication Bypass in Siemens Opcenter X (CVE-2026-56451)
slug: 2026-07-opcenter-x-jwt-bypass
description: A critical vulnerability, CVE-2026-56451, in Siemens Opcenter X versions prior to V2604 allows unauthenticated remote attackers to forge arbitrary JSON Web Tokens (JWTs) due to improper algorithm validation, leading to full authentication bypass, user impersonation including administrative accounts, and complete unauthorized access to the application.
date: "2026-07-14T10:18:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - authentication-bypass
  - jwt
  - remote-code-execution
  - critical-vulnerability
vendors:
  - Siemens AG
products:
  - Opcenter X (< V2604)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This could allow an unauthenticated remote attacker to forge arbitrary JWT, bypass authentication mechanisms and impersonate any user including administrative accounts, potentially gaining full unauthorized access to the application.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Affected applications do not properly validate the algorithm specified in the JSON Web Token (JWT) header. This could allow an unauthenticated remote attacker to forge arbitrary JWT, bypass authentication mechanisms and impersonate any user...
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: '...impersonate any user including administrative accounts, potentially gaining full unauthorized access to the application.'
    confidence_band: high
cves:
  - id: CVE-2026-56451
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56451
  - https://cert-portal.siemens.com/productcert/html/ssa-096828.html
---

A critical security vulnerability, identified as CVE-2026-56451, has been discovered in all versions of Siemens Opcenter X prior to V2604. This flaw originates from the application's failure to adequately validate the algorithm specified within the JSON Web Token (JWT) header during the authentication process. An unauthenticated remote attacker can exploit this weakness by crafting a malicious JWT where the algorithm is set to "none" or another insecure value, effectively bypassing the signature verification. Successful exploitation allows the attacker to forge arbitrary JWTs, impersonate any user, including administrative accounts, and gain full unauthorized access to the affected Opcenter X application. The vulnerability poses a severe risk, as it grants attackers complete control over the system without requiring any prior authentication or user interaction.

## Attack Chain

1. An unauthenticated remote attacker identifies an accessible Siemens Opcenter X instance vulnerable to CVE-2026-56451.
2. The attacker crafts a malicious JSON Web Token (JWT) intended for authentication with the Opcenter X application.
3. Within the JWT header, the attacker manipulates the `alg` (algorithm) parameter, setting it to an insecure value such as "none".
4. The attacker populates the JWT payload with claims, specifically the `sub` (subject) claim, to impersonate a legitimate user, potentially an administrative account.
5. The forged JWT, lacking a valid signature due to the "none" algorithm, is then submitted to the Opcenter X application's authentication endpoint.
6. Due to the vulnerability, the Opcenter X application improperly processes the JWT, failing to validate the integrity of the token's algorithm.
7. The application grants the attacker unauthorized access, treating the forged JWT as valid and bestowing the privileges of the impersonated user.
8. The attacker achieves full unauthorized access to the Opcenter X application, including administrative control and potentially sensitive data.

## Impact

The successful exploitation of CVE-2026-56451 results in a complete authentication bypass, granting unauthenticated remote attackers full control over the affected Siemens Opcenter X application. This includes the ability to impersonate any user, specifically administrative accounts, leading to unauthorized modification, deletion, or exfiltration of sensitive data, disruption of operations, and potentially further compromise of connected systems. Given the CVSSv3.1 score of 10.0, the impact is considered critical, presenting the highest risk of confidentiality, integrity, and availability compromise without any user interaction or prior authorization.

## Recommendation

* Immediately patch Siemens Opcenter X installations to version V2604 or later to remediate CVE-2026-56451.
* Monitor authentication logs for Siemens Opcenter X for any anomalous login attempts or successful authentications from unknown sources or highly privileged accounts.
* Implement Web Application Firewall (WAF) rules to detect and potentially block HTTP requests containing JWTs with known insecure `alg` parameters if possible, prior to reaching the application.
