---
title: CVE-2026-81702 Key Substitution in openssl_encrypt
slug: 2026-08-openssl-encrypt-identity-vuln
description: The openssl_encrypt library before 1.4.9 is vulnerable to key substitution attacks due to improper fingerprint validation when loading identities from local identity.json files.
date: "2026-08-27T19:09:25Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
products:
  - openssl_encrypt (< 1.4.9)
cves:
  - id: CVE-2026-81702
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81702
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade openssl_encrypt to 1.4.9 or higher.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-81702 advisory recommendation.
  mitigation_plan:
    - priority: immediate
      action: Restrict write access to identity.json files.
      owner: IT Operations
      addresses: CVE-2026-81702
      evidence: Source describes local file manipulation as the exploitation vector.
---

The openssl_encrypt library, specifically versions prior to 1.4.9, contains a critical vulnerability (CVE-2026-81702) in its identity management mechanism. When the library loads identity configurations from the 'identity.json' file, it fails to perform necessary re-derivation and validation of identity fingerprints. This design flaw allows an attacker with local file write access to substitute legitimate public keys with attacker-controlled keys within the identity store. Because the fingerprint validation is skipped or improperly performed, the library continues to associate the manipulated identity store with the original, expected fingerprint. This enables silent key substitution where systems perform encryption using attacker-provided keys while signature verification routines falsely report successful validation, creating significant risks for data interception, spoofing, and man-in-the-middle scenarios within applications relying on this library.

## Impact

Successful exploitation allows for the complete bypass of cryptographic identity verification. An attacker can intercept and decrypt sensitive communications or spoof legitimate entities by presenting a substituted public key that appears valid to the affected software. This poses a high risk of data breach and loss of integrity for any infrastructure or application utilizing openssl_encrypt for key-based authentication or encryption.

## Recommendation

- Upgrade openssl_encrypt to version 1.4.9 or higher across all affected applications immediately.
- Audit file system permissions for 'identity.json' files to ensure they are write-protected and accessible only by the service process owner.
- Scan environments for the presence of the 'identity.json' file to identify software components that rely on the vulnerable library implementation.
