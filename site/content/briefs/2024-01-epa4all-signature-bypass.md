---
title: epa4all-client Signature Verification Bypass Vulnerability
slug: 2024-01-epa4all-signature-bypass
description: epa4all-client is vulnerable to a signature verification bypass where the ECDSA signature verification discards the boolean return value, allowing any structurally valid signature to be considered trusted.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - signature-bypass
  - vulnerability
vendors:
  - Oviva AG
products:
  - epa4all-client (<= 1.2.0)
references:
  - https://github.com/advisories/GHSA-g8r3-5hwf-qp96
  - https://www.machinespirits.com/advisory/d76aec/
rules:
  - title: Detect epa4all-client Signature Verification Bypass Attempt (Process)
    description: Detects a process creation event where epa4all-client spawns a suspicious child process, potentially indicating exploitation of the signature verification bypass vulnerability (CVE-2026-44900).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect epa4all-client Signature Verification Bypass Attempt (File Modification)
    description: Detects a file modification event where epa4all-client modifies files outside its installation directory, potentially indicating exploitation of the signature verification bypass vulnerability (CVE-2026-44900).
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The `epa4all-client` software, specifically versions 1.2.0 and earlier, contains a critical vulnerability related to signature verification. The vulnerability resides in the `SignedPublicKeysTrustValidatorImpl.isTrusted()` method, where the return value of the `Signature.verify()` function, which indicates whether the signature matches, is ignored. This oversight means that any structurally valid signature, regardless of its authenticity, will be accepted as valid. This allows attackers to bypass signature validation checks. This vulnerability has been assigned CVE-2026-44900 and patched in pull request #34.

## Attack Chain

1. An attacker crafts a malicious update or component for `epa4all-client`.
2. The attacker signs the malicious component with any structurally valid signature (even if it's not cryptographically correct).
3. The compromised `epa4all-client` application receives the crafted, signed component.
4. The `SignedPublicKeysTrustValidatorImpl.isTrusted()` method is invoked to verify the signature of the component.
5. The `Signature.verify()` method is called, but its boolean return value is discarded.
6. Because the signature is structurally valid, the method proceeds as if the signature is authentic.
7. The malicious component is accepted and executed by the `epa4all-client` application.
8. The attacker achieves arbitrary code execution, potentially leading to data compromise or system takeover.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass signature validation, leading to the execution of malicious code within the `epa4all-client` application. This can lead to a complete compromise of the application, potentially affecting sensitive data handled by the client. The vulnerability affects versions 1.2.0 and earlier, potentially impacting all users of these versions.

## Recommendation

*   Upgrade to the patched version of `epa4all-client` referenced in [#34](https://github.com/oviva-ag/epa4all-client/pull/34) to remediate the signature bypass vulnerability.
*   Deploy the Sigma rule "Detect epa4all-client Signature Verification Bypass" to monitor for potential exploitation attempts.
*   Monitor network traffic for unusual activity originating from `epa4all-client` processes after upgrades, as this could indicate a compromised installation.
