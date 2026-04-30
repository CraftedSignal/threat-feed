---
title: fast-jwt Library JWT Algorithm Confusion Vulnerability
slug: 2026-04-fast-jwt-bypass
description: The fast-jwt library is vulnerable to JWT Algorithm Confusion via Whitespace-Prefixed RSA Public Key due to an incomplete fix for CVE-2023-48223, allowing attackers to bypass intended security measures by exploiting leading whitespace in the RSA public key, enabling attackers to sign arbitrary payloads that will be accepted by the verifier, potentially leading to privilege escalation.
date: "2026-04-03T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - jwt
  - algorithm-confusion
  - vulnerability
  - fast-jwt
  - nodejs
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2023-48223
    cvss: 5.9
    epss: 0.00184
references:
  - https://github.com/advisories/GHSA-mvf2-f6gm-w987
rules:
  - title: Detect HS256 Verification with RSA Key via Process Creation
    description: Detects potential exploitation attempts where an HS256 token is being verified with what appears to be an RSA key due to whitespace stripping bypass in fast-jwt. This rule uses process creation logs to identify the execution of Node.js processes using fast-jwt and attempting to verify tokens in this manner.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-34950
      - privilege_escalation
    techniques:
      - T1552
    data_sources:
      - process_creation
      - windows
  - title: Detect HS256 Verification with RSA Key via Command Line
    description: Detects potential exploitation attempts where an HS256 token is being verified with what appears to be an RSA key due to whitespace stripping bypass in fast-jwt. This rule uses command line parameters to identify the execution of Node.js processes using fast-jwt and attempting to verify tokens in this manner.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-34950
      - privilege_escalation
    techniques:
      - T1552
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The fast-jwt library, a popular Node.js package for handling JSON Web Tokens (JWTs), contains a vulnerability related to algorithm confusion. An incomplete fix for CVE-2023-48223 (GHSA-c2ff-88x2-x9pg) allows attackers to bypass intended security measures by exploiting leading whitespace in the RSA public key. Specifically, the `publicKeyPemMatcher` regex in `fast-jwt/src/crypto.js` does not account for leading whitespace, causing RSA public keys to be misclassified as HMAC secrets. This allows attackers to forge HS256 tokens using the RSA public key, leading to unauthorized access and privilege escalation. The vulnerability affects fast-jwt versions <= 6.1.0. This issue is a direct bypass of the fix for CVE-2023-48223.

## Attack Chain

1. The attacker identifies a server using the vulnerable fast-jwt library for JWT verification.
2. The attacker retrieves the server's RSA public key, which is often publicly available.
3. The attacker adds leading whitespace (e.g., a newline character) to the RSA public key.
4. The attacker crafts a malicious JWT with the header specifying the HS256 algorithm (`alg: 'HS256'`).
5. The attacker sets the payload of the JWT to contain desired claims, such as `admin: true`.
6. The attacker uses the whitespace-prefixed RSA public key as the HMAC secret to sign the JWT.
7. The attacker presents the forged HS256 token to the vulnerable server.
8. The server, due to the algorithm confusion vulnerability, incorrectly verifies the token using the RSA public key as an HMAC secret and grants unauthorized access based on the claims in the forged token.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass authentication and authorization controls, potentially gaining administrative privileges or access to sensitive data. This could lead to data breaches, system compromise, and reputational damage. The impact is significant due to the widespread use of the fast-jwt library in various applications. This is a direct bypass of the fix for CVE-2023-48223.

## Recommendation

*   Upgrade to a patched version of the `fast-jwt` library that addresses this vulnerability. This will require updating the `fast-jwt` package in your `package.json` file and redeploying your application.
*   As an immediate mitigation, sanitize RSA public keys by trimming leading whitespace before using them with the `fast-jwt` library. This can be done using the `.trim()` method in JavaScript before passing the key to the `createVerifier` function.
*   Deploy the Sigma rule that detects HS256 tokens being verified with RSA keys based on process creation logs to identify potential exploitation attempts.
*   Implement logging and monitoring for JWT verification processes to detect anomalies and suspicious activity. Specifically, monitor for instances where HS256 is used with keys that appear to be RSA public keys.
*   Review and update any existing security controls related to JWT handling to ensure they are effective against this type of algorithm confusion attack.
