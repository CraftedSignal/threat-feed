---
title: PyJWT Asymmetric-PEM Detection Bypass Leading to Algorithm Confusion
slug: 2026-09-pyjwt-pem-bypass
description: An incomplete asymmetric-key guard in PyJWT (CVE-2026-102268) allows specially formatted public keys to be used as HMAC secrets, enabling universal token forgery when applications misconfigure algorithm allow-lists.
date: "2026-09-30T04:18:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:pyjwt_project:pyjwt:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*
tags:
  - jwt
  - authentication-bypass
  - cve-2026-102268
  - library-vulnerability
products:
  - PyJWT (<= 2.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.002
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who knows only the public verification key forges arbitrary-claim tokens that verify as authentic.
    confidence_band: high
cves:
  - id: CVE-2026-102268
    cvss: 9.1
  - id: CVE-2022-29217
    cvss: 7.4
    epss: 0.01355
references:
  - https://github.com/advisories/GHSA-ffc3-869f-jxw9
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102268
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Upgrade PyJWT to 2.14.0 or later
      owner: IT Operations
      due: 24h
      evidence: Maintainer release notes specify 2.14.0 contains the fix.
  mitigation_plan:
    - priority: immediate
      action: Remove HMAC algorithms from allow-lists that accept asymmetric keys
      owner: AppSec
      addresses: CVE-2026-102268
      evidence: Source document identifies mixed algorithm allow-lists as the primary precondition for exploitation.
---

PyJWT versions 2.13.0 and earlier contain a security bypass in the `is_pem_format` utility that allows asymmetric public keys to be treated as symmetric HMAC secrets. This occurs because the library's internal regex-based PEM validator is overly strict, failing to recognize PEM-formatted keys that include marker-adjacent whitespace, bare carriage returns, or single-line folding. While the `cryptography` library correctly parses these mutated keys, PyJWT's guard mechanism - intended to prevent CVE-2022-29217 algorithm confusion - erroneously concludes they are not asymmetric keys. If an application's `jwt.decode` configuration includes both HMAC (e.g., HS256) and asymmetric algorithms, an attacker can leverage the public key as an HMAC secret to mint valid tokens with arbitrary claims. This vulnerability is critical for applications that fail to follow RFC 8725 best practices regarding algorithm allow-listing.

## Attack Chain

1. The attacker identifies an application that performs JWT verification with an overly permissive algorithm allow-list containing both asymmetric (e.g., RS256/ES256) and symmetric (e.g., HS256) algorithms.
2. The attacker obtains the application's public verification key.
3. The attacker applies specific whitespace or line-ending mutations to the public key PEM to bypass PyJWT's `is_pem_format` regex validation.
4. The attacker sends a malicious JWT, using the mutated public key as the HMAC shared secret to sign the token with `alg=HS256`.
5. The target application receives the JWT and passes the mutated key to `PyJWT.decode`.
6. The `HMACAlgorithm.prepare_key` function checks the mutated key against `is_pem_format`, which returns `False` due to the mutation.
7. The guard logic is bypassed, allowing the public key bytes to be used directly as the HMAC secret.
8. The application verifies the forged token as authentic, resulting in unauthorized access or privilege escalation.

## Impact

Successful exploitation allows for universal token forgery, enabling an attacker to bypass authentication and impersonate any user, including high-privileged accounts. The vulnerability affects any service using PyJWT where developers have combined symmetric and asymmetric algorithms in the verification allow-list. While no active real-world incident was documented in the advisory, the potential impact is critical for any system relying on affected versions of PyJWT for identity or session management.

## Recommendation

1. Upgrade PyJWT to version 2.14.0 or later immediately to incorporate the fix for CVE-2026-102268.
2. Audit all JWT verification logic to ensure algorithm allow-lists strictly adhere to RFC 8725, explicitly separating symmetric and asymmetric key paths.
3. Avoid mixing HMAC and RSA/ECDSA algorithms in a single allow-list entry.
4. Transition to the `PyJWK` verification path, which enforces strict algorithm binding and is unaffected by this vulnerability.
