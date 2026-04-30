---
title: Forge Ed25519 Signature Forgery Vulnerability
slug: 2026-09-forge-ed25519-forgery
description: Forge is vulnerable to signature forgery in Ed25519 due to a missing check that S < L, allowing non-canonical signatures and potentially bypassing authentication/authorization logic, affecting versions before 1.4.0.
date: "2026-03-26T22:08:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ed25519
  - signature-forgery
  - forge
  - javascript
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-q67f-28xg-22rw
  - https://datatracker.ietf.org/doc/html/rfc8032#section-8.4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33895
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25793
  - https://nvd.nist.gov/vuln/detail/CVE-2022-35961
rules:
  - title: Detect Forged Ed25519 Signatures via Modified S Value
    description: Detects potential attempts to use non-canonical Ed25519 signatures where the 'S' value has been manipulated.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - application
      - forge
  - title: Detect Ed25519 Signature Verification with Forge Library
    description: Detects the usage of the Forge library for Ed25519 signature verification, which might be vulnerable to CVE-2026-33895.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - application
      - forge
rules_count: 2
---

The Forge library, a popular JavaScript cryptography toolkit, exhibits a signature forgery vulnerability in its Ed25519 implementation. Specifically, the verification process lacks a critical check to ensure that the scalar 'S' is less than the group order 'L' (S < L). This omission enables the acceptance of non-canonical signatures, effectively forging signatures. This vulnerability affects Forge versions prior to 1.4.0. An attacker could exploit this flaw to bypass security mechanisms that rely on the uniqueness of cryptographic signatures, such as authentication systems, replay protection, and signed-object canonicalization checks. This is especially critical for applications assuming that valid signatures are unique. The issue was identified in commit `8e1d527fe8ec2670499068db783172d4fb9012e5` and has been present since the introduction of Ed25519 support.

## Attack Chain

1.  The attacker identifies an application using Forge's Ed25519 implementation for signature verification.
2.  The attacker obtains a valid Ed25519 signature for a specific message using a legitimate key pair.
3.  The attacker manipulates the valid signature by adding the Ed25519 group order 'L' to the 'S' component of the signature (bytes 32-63), creating a non-canonical signature.
4.  The attacker submits the forged, non-canonical signature to the vulnerable application for verification.
5.  The Forge library, due to the missing 'S < L' check, incorrectly validates the forged signature as authentic.
6.  The vulnerable application accepts the forged signature, potentially granting unauthorized access or allowing malicious actions.
7.  The attacker successfully bypasses authentication or authorization controls that rely on signature validation.

## Impact

Successful exploitation of this vulnerability can lead to a bypass of authentication and authorization mechanisms in applications that rely on Forge's Ed25519 implementation for signature verification. This could result in unauthorized access to sensitive data, account compromise, or the execution of malicious commands. The number of affected applications is potentially significant, given Forge's widespread use in JavaScript-based systems. This is further compounded by the vulnerability existing since the initial implementation of Ed25519 in the library. The impact of this vulnerability will vary, depending on how signatures are used within the application. Applications that depend on unique signatures for integrity checks are at significant risk.

## Recommendation

*   Upgrade to Forge version 1.4.0 or later, which includes a fix for CVE-2026-33895 (https://nvd.nist.gov/vuln/detail/CVE-2026-33895).
*   Apply the provided patch to earlier versions of Forge to enforce strict canonical scalar validation in the Ed25519 verification path.
*   Deploy the Sigma rule "Detect Forged Ed25519 Signatures via Modified S Value" to identify attempts to exploit this vulnerability.
*   Audit applications using Forge to identify and remediate any reliance on signature uniqueness for security-critical functions.
