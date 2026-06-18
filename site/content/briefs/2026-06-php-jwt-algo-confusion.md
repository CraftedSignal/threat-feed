---
title: PHP JWT Framework Algorithm Confusion Vulnerability (TOCTOU)
slug: 2026-06-php-jwt-algo-confusion
description: A Time-of-Check/Time-of-Use (TOCTOU) vulnerability exists in the `JWSVerifier` and `JWEDecrypter` components of the `web-token/jwt-framework` and `web-token/jwt-library` PHP packages, allowing an attacker to override the integrity-protected `alg` parameter from the unprotected header, leading to authentication bypass and unauthorized access.
date: "2026-06-18T21:14:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - php
  - jwt
  - web
  - authentication-bypass
vendors:
  - composer/web-token
products:
  - jwt-framework <= 4.2.99
  - jwt-library < 3.4.10
  - jwt-library >= 4.0.0, < 4.0.7
  - jwt-library >= 4.1.0, < 4.1.7
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1213
    technique_name: Exploitation for Credential Access
references:
  - https://github.com/advisories/GHSA-jc38-x7x8-2xc8
rules:
  - title: Detect JWT Algorithm Verification Errors
    description: Detects application log entries indicating errors during JWT algorithm verification, which could signify an attempt to exploit the algorithm confusion vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1213
      - T1562.001
    data_sources:
      - webserver
  - title: Detect JWT 'none' Algorithm Usage
    description: Detects attempts to process JSON Web Tokens (JWTs) using the 'none' algorithm, which is highly suspicious in security-sensitive contexts and could indicate an exploitation attempt of the algorithm confusion vulnerability or a misconfiguration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1213
      - T1562.001
    data_sources:
      - webserver
rules_count: 2
---

The `web-token/jwt-framework` and `web-token/jwt-library` PHP packages are affected by a Time-of-Check/Time-of-Use (TOCTOU) vulnerability that allows attackers to perform algorithm confusion attacks. Specifically, in `JWSVerifier::getAlgorithm()` and `JWEDecrypter`, header merging logic (`...` spread operator or `array_merge()`) incorrectly prioritizes the unprotected `alg` (algorithm) parameter over the integrity-protected one when duplicate keys exist. This means that while the protected header's `alg` might be validated (e.g., `RS256`), the actual signature verification or decryption might proceed with an attacker-specified `alg` from the unprotected header (e.g., `HS256` or `none`). This bypasses cryptographic integrity checks, enabling authentication bypass, unauthorized access, or information disclosure, making it critical for applications relying on these libraries for secure JWT handling.

## Attack Chain

1.  **Initial Access / Reconnaissance:** An attacker identifies a web application utilizing JSON Web Tokens (JWTs) for authentication or authorization.
2.  **Malicious JWT Creation:** The attacker crafts a JWT containing a protected header with a strong, integrity-protected algorithm (e.g., `alg: RS256`) and an unprotected header specifying a weaker or symmetric algorithm (e.g., `alg: HS256` or `alg: none`), intending for the unprotected `alg` to override the protected one.
3.  **Token Submission:** The attacker sends this crafted, malicious JWT to the vulnerable web application, typically within an HTTP `Authorization` header or as a cookie.
4.  **Header Merging (TOCTOU):** Upon receiving the JWT, the application's `JWSVerifier` or `JWEDecrypter` component merges the protected and unprotected headers. Due to the vulnerability, the `alg` parameter from the unprotected header overwrites the `alg` from the protected header in the internal merged array.
5.  **Algorithm Validation (Time-of-Check):** An initial check (e.g., by `HeaderCheckerManager`) might validate the `alg` from the *protected* header (e.g., `RS256`), which passes, creating a false sense of security.
6.  **Signature/Decryption (Time-of-Use):** The `JWSVerifier` or `JWEDecrypter` proceeds to verify the JWT signature (or decrypt the payload) using the `alg` parameter that was *overridden* by the unprotected header (e.g., `HS256` or `none`).
7.  **Authentication Bypass / Data Compromise:** If the attacker chose an `alg` like `none` or could forge a valid signature for a symmetric key (`HS256`), the system may successfully validate the JWT.
8.  **Impact:** This leads to unauthorized access, impersonation of legitimate users, or decryption of sensitive data, allowing the attacker to bypass authentication mechanisms.

## Impact

If exploited, this vulnerability leads to a severe authentication bypass, allowing attackers to forge valid JSON Web Tokens (JWTs) and gain unauthorized access to web applications. This could result in full account takeover, privilege escalation, and access to sensitive data or functionality that should be restricted. The impact is significant for applications that rely on `web-token/jwt-framework` or `web-token/jwt-library` for secure session management, API authentication, or inter-service communication. Organizations across all sectors using PHP applications with these specific JWT libraries are at risk, as the integrity of their authentication and authorization mechanisms is compromised.

## Recommendation

*   Immediately update `composer/web-token/jwt-framework` to a patched version (e.g., newer than 4.2.99) to address the algorithm confusion vulnerability.
*   Immediately update `composer/web-token/jwt-library` to a patched version (e.g., >= 3.4.10, >= 4.0.7, >= 4.1.7) to address the algorithm confusion vulnerability.
*   Review application logs for entries indicating JWT verification failures or unexpected algorithm usage for authentication (refer to the `Detect JWT Algorithm Verification Errors` rule).
*   Ensure verbose application logging is enabled for JWT processing and verification steps to aid in detection of anomalous `alg` parameter usage (refer to the `Detect JWT 'none' Algorithm Usage` rule).
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically for `webserver` logs that might contain application-level JWT processing details.
