---
title: Bleichenbacher Oracle Vulnerability in cryptography Library
slug: 2026-08-cryptography-pkcs7-oracle
description: The cryptography library fails to perform constant-time operations during PKCS#7 EnvelopedData decryption, creating a Bleichenbacher oracle that allows attackers to recover content-encryption keys via error and timing analysis (CVE-2026-69247).
date: "2026-08-03T23:41:53Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - cryptography (>= 44.0.0, < 50.0.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: An application that decrypts attacker-supplied EnvelopedData and reflects the outcome gives the attacker a Bleichenbacher oracle against the content-encryption key.
    confidence_band: high
cves:
  - id: CVE-2026-69247
references:
  - https://github.com/advisories/GHSA-g6cj-pr64-35w5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69247
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Patch cryptography library to 50.0.0
      owner: IT Operations
      due: 48h
      evidence: Fixed in 50.0.0
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate services that auto-decrypt untrusted EnvelopedData
      owner: Application Security
      addresses: CVE-2026-69247
      evidence: Exploitation requires a service that auto-decrypts untrusted EnvelopedData
---

The cryptography Python library, specifically versions 44.0.0 through 49.x.x, contains a critical vulnerability in its PKCS#7 EnvelopedData decryption routines (`pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, and `pkcs7_decrypt_smime`). The library performs RSA PKCS#1 v1.5 decryption on an `encryptedKey` and subsequently decrypts the content using the resulting key. 

Defenders should note that the implementation reveals distinct error messages and timing discrepancies based on whether the decryption process fails due to padding, key size mismatch, or invalid padding bytes. These side channels function as a Bleichenbacher oracle. An attacker providing untrusted `EnvelopedData` to a service that automatically processes and reflects these decryption outcomes (such as an S/MIME gateway or automated mail filter) can iteratively recover the content-encryption key. This is caused by a failure to comply with RFC 3218 recommendations for constant-time failure handling and uniform error responses.

## Impact

Successful exploitation allows for the recovery of content-encryption keys used in PKCS#7 protected data. This vulnerability affects any environment utilizing the `cryptography` library version 44.0.0 to 49.x.x to process untrusted S/MIME or EnvelopedData content. The impact is significant for secure messaging gateways and automated data processing pipelines that interact with external, potentially malicious, encrypted payloads.

## Recommendation

* Update the `cryptography` library to version 50.0.0 or later immediately to implement RFC 3218-compliant constant-time decryption and uniform error reporting.
* Audit applications utilizing `cryptography` to determine if they automatically decrypt and reflect errors or processing results of untrusted `EnvelopedData` to external entities.
* Restrict the ability of automated systems to process untrusted `EnvelopedData` until the library patch is applied to mitigate the risk of automated oracle queries.
