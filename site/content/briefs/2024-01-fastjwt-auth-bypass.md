---
title: fast-jwt Authentication Bypass Vulnerability via Empty HMAC Secret
slug: 2024-01-fastjwt-auth-bypass
description: A critical vulnerability in the fast-jwt library allows attackers to forge JWTs by exploiting the acceptance of empty HMAC secrets in the async key resolver, leading to authentication bypass.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - jwt
  - authentication-bypass
  - vulnerability
  - fast-jwt
vendors:
  - npm
products:
  - fast-jwt (<= 6.2.3)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-gmvf-9v4p-v8jc
rules:
  - title: Detect JWT with Empty Key ID (kid)
    description: Detects JWTs with an empty key ID (kid) which can be indicative of an attempt to exploit CVE-2026-44351. This rule identifies JWTs where the 'kid' field in the header is either missing or an empty string.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
  - title: Detect JWT with common header, for empty-key HMAC SHA256
    description: Detects JWTs forged with the most common empty key HMAC, as described in CVE-2026-44351. This rule detects an attempt to sign a forged JWT using an empty key.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1550.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `fast-jwt` library, up to version 6.2.3, contains a critical authentication bypass vulnerability that allows an attacker to forge JWTs. This occurs when the application uses an asynchronous key resolver that can return an empty string ('') or zero-length buffer. When `fast-jwt` receives this empty value, it incorrectly derives allowed HMAC algorithms and proceeds to verify the token against an empty key, effectively bypassing authentication. This flaw can be exploited in scenarios using the JWKS pattern, where a key ID (kid) lookup might result in an empty string if the key is not found. The vulnerability allows attackers to mint arbitrary JWTs, assuming any identity within the application.

## Attack Chain

1. The attacker crafts a JWT with a chosen header and payload, including malicious claims such as `admin: true`.
2. The attacker sets the `kid` (key ID) in the JWT header to a value that will result in an empty string lookup in the application's key resolver (e.g., an unknown `kid`).
3. The attacker computes the HMAC-SHA256 signature of the JWT header and payload using an empty string as the key.
4. The attacker presents the forged JWT to the vulnerable application.
5. The application's async key resolver receives the JWT and attempts to retrieve the key based on the `kid`.
6. The key resolver returns an empty string ('') or zero-length buffer because the `kid` is not found.
7. `fast-jwt` converts the empty string to a zero-length Buffer and uses it to create an HMAC secret key. It also determines the allowed algorithms as HS256, HS384 and HS512.
8. `fast-jwt` verifies the forged JWT's signature against the empty key, which succeeds because the attacker used an empty key to create the signature.
9. The application accepts the forged JWT as authentic, granting the attacker the privileges associated with the claims in the token.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass authentication and assume any identity within the application. This can lead to unauthorized access to sensitive data, privilege escalation, and other malicious activities. Any Node.js application using fast-jwt with a function-typed `key` resolver and the JWKS pattern is potentially vulnerable. The impact is significant because the attacker can mint arbitrary JWTs with attacker-chosen claims (sub, admin, roles, scopes, etc.) leading to full identity assumption. Default configurations are exploitable. Once a forged token is accepted, fast-jwt caches the verification result, amplifying the impact.

## Recommendation

*   Upgrade to a patched version of `fast-jwt` that addresses CVE-2026-44351.
*   Apply the suggested fix by rejecting zero-length HMAC secrets in `prepareKeyOrSecret` as described in the advisory.
*   If upgrading is not immediately possible, modify the application's key resolver to explicitly reject empty strings or zero-length buffers and return an error.
*   Deploy the Sigma rules in this brief to your SIEM to detect attempts to exploit this vulnerability.
*   Monitor web server logs for suspicious JWTs with empty or invalid `kid` values.
