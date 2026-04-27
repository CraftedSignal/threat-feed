---
title: fast-jwt Library JWT Algorithm Confusion Vulnerability
slug: 2026-04-fast-jwt-bypass
description: The fast-jwt library is vulnerable to JWT Algorithm Confusion via Whitespace-Prefixed RSA Public Key due to an incomplete fix for CVE-2023-48223, allowing attackers to bypass intended security measures by exploiting leading whitespace in the RSA public key, enabling attackers to sign arbitrary payloads that will be accepted by the verifier, potentially leading to privilege escalation.
date: "2026-04-03T12:00:00Z"
severities:
  - critical
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

The fast-jwt library, a popular Node.js package for handling JSON Web Tokens (JWTs), contains a vulnerability related to algorithm confusion. An incomplete fix for CVE-2023-48223 (GHSA-c2ff-88x2-x9pg) allows attackers to bypass intended security measures by exploiting leading whitespace in the RSA public key. Specifically, the `publicKeyPemMatcher` regex in `fast-jwt/src/crypto.js` does not account for leading whitespace, causing RSA public keys to be misclassified as HMAC secrets. This allows…
