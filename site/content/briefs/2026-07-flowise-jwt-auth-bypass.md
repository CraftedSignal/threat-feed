---
title: Flowise Authentication Bypass via Hardcoded JWT Secrets (CVE-2026-56271)
slug: 2026-07-flowise-jwt-auth-bypass
description: Flowise versions 3.0.13 and earlier are vulnerable due to hardcoded default JWT secrets ('auth_token', 'refresh_token') and default audience/issuer values ('AUDIENCE', 'ISSUER'), allowing an attacker to forge valid JWTs and impersonate any user, including administrators, leading to an authentication bypass if environment variables are not explicitly set.
date: "2026-07-12T12:18:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - jwt
  - hardcoded-credentials
  - web-application
  - critical-vulnerability
vendors:
  - Flowise
products:
  - Flowise (< 3.1.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: allowing an attacker to forge valid JWTs and impersonate any user, including administrators, resulting in authentication bypass.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allowing an attacker to forge valid JWTs and impersonate any user, including administrators
    confidence_band: high
cves:
  - id: CVE-2026-56271
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56271
---

CVE-2026-56271 describes a critical authentication bypass vulnerability affecting Flowise versions 3.0.13 and earlier. The flaw originates from the application's enterprise passport authentication middleware, which utilizes weak, hardcoded default JWT secrets, 'auth_token' and 'refresh_token', along with default audience and issuer values, 'AUDIENCE' and 'ISSUER'. If corresponding environment variables, specifically `JWT_AUTH_TOKEN_SECRET`, `JWT_REFRESH_TOKEN_SECRET`, `JWT_AUDIENCE`, and `JWT_ISSUER`, are not explicitly configured by the user, Flowise silently reverts to these publicly known default values. This oversight allows an unauthenticated attacker to craft and sign valid JSON Web Tokens (JWTs) using these predictable secrets and values. By presenting a forged JWT, an attacker can bypass authentication mechanisms, impersonate any user, including administrators, and gain unauthorized access to the Flowise instance. This vulnerability poses a severe risk to the integrity and confidentiality of data managed by affected Flowise deployments.

## Attack Chain

1. An attacker identifies a publicly accessible Flowise instance.
2. The attacker determines the Flowise instance is running a vulnerable version (3.0.13 or earlier).
3. The attacker crafts a JSON Web Token (JWT) payload designed to impersonate an administrative user within the Flowise application.
4. The attacker signs this forged JWT using the publicly known hardcoded default secrets ('auth_token' or 'refresh_token') and incorporates the default audience ('AUDIENCE') and issuer ('ISSUER') values.
5. The attacker sends an HTTP request to the Flowise instance, including the forged JWT in the `Authorization` header.
6. The Flowise application, if operating with default environment variables, validates the forged JWT as legitimate due to the predictable secrets and values.
7. The application grants the attacker administrative privileges, believing the forged token to be valid.
8. The attacker gains full control over the Flowise instance, enabling unauthorized configuration changes, data exfiltration, or deployment of malicious AI flows.

## Impact

Successful exploitation of CVE-2026-56271 results in a complete authentication bypass, granting attackers administrative access to the Flowise application. This allows for full compromise of the affected instance, including the ability to read, modify, or delete sensitive data, reconfigure system settings, or deploy arbitrary code through malicious AI flows. Given the nature of Flowise as a low-code platform for AI applications, this could lead to significant data breaches, intellectual property theft, or the use of compromised infrastructure for further attacks. The vulnerability carries a CVSS v3.1 Base Score of 9.8, indicating critical severity and a high potential for widespread, severe damage.

## Recommendation

* Patch CVE-2026-56271 immediately by upgrading all Flowise instances to version 3.1.0 or newer.
* Verify and immediately set unique and strong values for the `JWT_AUTH_TOKEN_SECRET`, `JWT_REFRESH_TOKEN_SECRET`, `JWT_AUDIENCE`, and `JWT_ISSUER` environment variables in all Flowise deployments, ensuring they are not using the publicly known defaults.
