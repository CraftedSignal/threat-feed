---
title: CVE-2026-81702 Key Substitution in openssl_encrypt
slug: 2026-08-openssl-encrypt-identity-vuln
description: The openssl_encrypt library before 1.4.9 is vulnerable to key substitution attacks due to improper fingerprint validation when loading identities from local identity.json files.
date: "2026-08-27T19:09:25Z"
lastmod: "2026-08-27T19:11:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
vendors:
  - OpenSSL
products:
  - openssl_encrypt (< 1.4.9)
  - openssl-encrypt (<= 1.4.8)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The openssl-encrypt pip package versions 1.4.8 and earlier store an mTLS client private key in cleartext within a world-readable (0644) SharedPreferences file.
    confidence_band: high
cves:
  - id: CVE-2026-81702
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81702
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81707
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81683
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81688
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
updates:
  - at: "2026-08-27T19:09:33Z"
    level: L2
    summary: added coverage for openssl_encrypt (< 1.4.9)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-81707
  - at: "2026-08-27T19:10:54Z"
    level: L2
    summary: added coverage for openssl-encrypt (<= 1.4.8)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-81683
  - at: "2026-08-27T19:11:00Z"
    level: L2
    summary: added coverage for openssl_encrypt (< 1.4.9)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-81688
---

The openssl_encrypt library, specifically versions prior to 1.4.9, contains a critical vulnerability (CVE-2026-81702) in its identity management mechanism. When the library loads identity configurations from the 'identity.json' file, it fails to perform necessary re-derivation and validation of identity fingerprints. This design flaw allows an attacker with local file write access to substitute legitimate public keys with attacker-controlled keys within the identity store. Because the fingerprint validation is skipped or improperly performed, the library continues to associate the manipulated identity store with the original, expected fingerprint. This enables silent key substitution where systems perform encryption using attacker-provided keys while signature verification routines falsely report successful validation, creating significant risks for data interception, spoofing, and man-in-the-middle scenarios within applications relying on this library.

## Impact

Successful exploitation allows for the complete bypass of cryptographic identity verification. An attacker can intercept and decrypt sensitive communications or spoof legitimate entities by presenting a substituted public key that appears valid to the affected software. This poses a high risk of data breach and loss of integrity for any infrastructure or application utilizing openssl_encrypt for key-based authentication or encryption.

## Recommendation

- Upgrade openssl_encrypt to version 1.4.9 or higher across all affected applications immediately.
- Audit file system permissions for 'identity.json' files to ensure they are write-protected and accessible only by the service process owner.
- Scan environments for the presence of the 'identity.json' file to identify software components that rely on the vulnerable library implementation.
