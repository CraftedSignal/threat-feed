---
title: PHP JWT Library PBES2-HS*+A*KW Unbounded p2c Iteration Count Leads to DoS
slug: 2026-06-php-jwt-pbes2-dos
description: An unauthenticated attacker can exploit a vulnerability in the PHP JWT Library's PBES2AESKW::unwrapKey() function when processing JWE tokens that use PBES2-HS*+A*KW algorithms by crafting a JWE with an excessively large 'p2c' (PBKDF2 iteration count) parameter in the JOSE header, forcing the server to perform an unbounded and CPU-intensive PBKDF2 computation, resulting in a CPU-amplification denial of service.
date: "2026-06-18T21:15:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - web
  - php
  - jwt
  - jwe
  - cwe-400
vendors:
  - composer/web-token
products:
  - jwt-library (< 3.4.10)
  - jwt-framework (<= 4.1.6)
  - jwt-library (>= 4.0.0, < 4.0.7)
  - jwt-library (>= 4.1.0, < 4.1.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-3prj-6hqw-cm82
  - https://www.rfc-editor.org/rfc/rfc7518#section-4.8
  - https://cwe.mitre.org/data/definitions/400.html
rules:
  - title: Detect PHP JWT Library PBES2 Algorithm Usage in HTTP Requests
    description: Detects HTTP requests that contain JSON Web Encryption (JWE) tokens leveraging PBES2 algorithms in their JOSE header. This indicates that the application might be vulnerable to the unbounded p2c iteration count DoS if the PHP JWT library is not patched.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
  - title: Detect PHP JWT Library DoS Exploitation - Large p2c Parameter in JWE
    description: Detects HTTP requests containing JWEs with an unusually large 'p2c' (PBKDF2 iteration count) value in their JOSE header (e.g., 8 digits or more), indicative of an attempted CPU-amplification denial-of-service attack against the PHP JWT Library.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 2
---

A high-severity denial-of-service vulnerability (CWE-400) has been discovered in the PHP JWT Library (composer/web-token/jwt-library and jwt-framework), affecting versions prior to 3.4.10, 4.0.7, and 4.1.7. This flaw allows an unauthenticated attacker to trigger an unbounded CPU consumption on a server processing JSON Web Encryption (JWE) tokens. Specifically, when JWEs utilize password-based key-encryption algorithms (PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW), the `PBES2AESKW::unwrapKey()` function reads the `p2c` (PBKDF2 iteration count) parameter directly from the attacker-controlled JOSE header. The absence of an upper bound on this parameter allows attackers to specify extremely high iteration counts (e.g., 100,000,000 or PHP_INT_MAX), causing the server to expend significant CPU resources on PBKDF2 computations before any key unwrapping validation occurs. This resource exhaustion can lead to severe service degradation or unavailability for targeted applications.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious JSON Web Encryption (JWE) token.
2.  The attacker manipulates the protected JOSE header of the JWE to include a `p2c` (PBKDF2 iteration count) parameter with an arbitrarily large integer value (e.g., `100,000,000` or `PHP_INT_MAX`).
3.  The attacker sends this crafted JWE token to a vulnerable application endpoint (e.g., via an HTTP header, request body, or URL parameter).
4.  The vulnerable PHP JWT Library receives the JWE and attempts to process it using a registered PBES2-HS*+A*KW algorithm for key unwrapping.
5.  The `PBES2AESKW::unwrapKey()` function extracts the `p2c` value from the JOSE header without adequate upper bound validation, as only `is_int($p2c) && $p2c > 0` is checked.
6.  The function initiates `hash_pbkdf2()` with the excessively large `p2c` value, forcing the server's CPU to perform an intensive, prolonged computation for PBKDF2 key derivation.
7.  The server worker process becomes stalled, consuming significant CPU resources for an extended period (potentially tens of seconds per request), leading to resource exhaustion.
8.  If sufficient malicious JWEs are processed, the application or server becomes unresponsive, resulting in a denial-of-service condition due to uncontrolled resource consumption.

## Impact

Successful exploitation of this vulnerability leads to a severe denial-of-service (DoS) condition. Attackers can force target servers to dedicate substantial CPU resources to perform computationally expensive PBKDF2 iterations, effectively stalling worker processes. This resource exhaustion prevents legitimate users from accessing the application, resulting in service unavailability and potential data loss if stateful operations are interrupted. While the vulnerability description does not specify observed victim counts or sectors, any application utilizing the affected PHP JWT Library and configured to accept JWEs with PBES2 algorithms is at risk, particularly those exposed to unauthenticated input. The cost to the attacker for generating the malicious JWE is negligible compared to the server's computational burden.

## Recommendation

*   Upgrade the `composer/web-token/jwt-library` to versions 3.4.10, 4.0.7, or 4.1.7, or `composer/web-token/jwt-framework` to version 4.1.7 or later, which enforce a `DEFAULT_MAX_COUNT = 1_000_000` for `p2c`.
*   If immediate upgrade is not feasible, implement a custom header checker to validate and limit the `p2c` header parameter for JWEs before they are processed by the vulnerable library, as described in the source.
*   Disable PBES2 algorithms for JWE decryption if they are not strictly required, especially for tokens originating from untrusted sources.
*   Deploy the provided Sigma rules to your SIEM to detect attempts to exploit this vulnerability or identify applications configured to use the affected PBES2 algorithms.
*   Monitor web server and PHP application logs for HTTP requests containing JWEs that use PBES2 algorithms or include abnormally large `p2c` values, as described in the detection rules.
