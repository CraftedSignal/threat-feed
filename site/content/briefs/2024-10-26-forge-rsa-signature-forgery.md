---
title: Forge RSA Signature Forgery Vulnerability
slug: 2024-10-26-forge-rsa-signature-forgery
description: Forge is vulnerable to signature forgery in RSA-PKCS due to ASN.1 extra field, allowing attackers to forge signatures by stuffing garbage bytes within the ASN structure for low public exponent keys (e=3), enabling Bleichenbacher style forgery and affecting npm/node-forge versions less than 1.4.0.
date: "2024-10-26T12:00:00Z"
lastmod: "2026-09-03T19:22:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - forge
  - rsa
  - signature-forgery
  - bleichenbacher
vendors:
  - Digital Bazaar
products:
  - node-forge (<= 1.4.0)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
cves:
  - id: CVE-2026-85393
  - id: CVE-2026-33894
references:
  - https://github.com/advisories/GHSA-ppp5-5v6c-4jwp
  - https://github.com/digitalbazaar/forge/security/advisories/GHSA-cfm4-qjh2-4765
  - https://datatracker.ietf.org/doc/html/rfc2313#section-8
  - https://www.rfc-editor.org/rfc/rfc8017.html
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85393
rules:
  - title: Detect Forge RSA Signature Forgery
    description: Detects potential exploitation attempts of the Forge RSA signature forgery vulnerability by looking for suspicious process execution patterns indicative of the exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Vulnerable Forge Library Usage
    description: Detects the usage of vulnerable Forge library versions by monitoring script executions that import the library.
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-09-03T19:22:58Z"
    level: L2
    summary: added CVE-2026-33894 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85393
---

The Forge library is susceptible to a signature forgery vulnerability in its RSA-PKCS#1 v1.5 signature verification process. This flaw allows attackers to forge signatures, particularly when low public exponent keys (e=3) are used. The vulnerability stems from the library's acceptance of "garbage" bytes within the ASN.1 structure of the signature, enabling Bleichenbacher-style forgeries. This issue is similar to CVE-2022-24771 but involves adding bytes within the ASN.1 structure instead of outside it. Furthermore, Forge fails to validate that signatures include a minimum of 8 bytes of padding as defined by RFC 2313, providing attackers with additional space for constructing forgeries. This affects deployments using `npm/node-forge` versions less than 1.4.0, specifically tested on v1.3.3 and recent prior versions.

## Attack Chain

1. The attacker crafts a malicious payload, targeting systems using the vulnerable Forge library for RSA signature verification.
2. The attacker generates a fresh RSA keypair (4096 bits, e=3) using the crypto library in Node.js.
3. The attacker computes a forged signature candidate by constructing a malicious ASN.1 structure with garbage bytes, exploiting the ASN.1 parsing vulnerability within Forge's `_parseAllDigestBytes` function.
4. The attacker leverages cube-root interval construction, to compute a forged candidate and generates a PKCS#1 v1.5 signature block that bypasses Forge’s validation.
5. Forge's `key.verify` function processes the forged signature with the default RSASSA-PKCS1-v1_5 scheme and `_parseAllDigestBytes: true`.
6. Due to the vulnerability, Forge incorrectly validates the forged signature, even though it contains extraneous data within the ASN.1 structure.
7. Node/OpenSSL verification, used as a baseline, rejects the forged signature, highlighting the discrepancy.
8. Successful exploitation leads to bypassing signature verification, potentially allowing unauthorized code execution or data manipulation, depending on the application's use of Forge.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass signature verification checks in applications using the Forge library. This could lead to unauthorized access, code execution, or data manipulation. Given the widespread use of Forge in various JavaScript-based applications, the impact could be significant, affecting numerous systems and users. The vulnerability has been assigned CVE-2026-33894 with a severity rating of High. Affected packages include npm/node-forge versions less than 1.4.0.

## Recommendation

*   Upgrade the `npm/node-forge` package to version 1.4.0 or later to remediate CVE-2026-33894.
*   Apply the provided patch to enforce PKCS#1 v1.5 BT=0x01 minimum padding length (`PS >= 8`) in `_decodePkcs1_v1_5` as described in the Suggested Patch section.
*   Update the RSASSA-PKCS1-v1_5 verifier to require canonical DigestInfo structure only (no extra attacker-controlled ASN.1 content beyond expected fields) as described in the Suggested Patch section.
*   Deploy the Sigma rule `Detect Forge RSA Signature Forgery` to identify exploitation attempts based on process execution patterns.
*   Monitor web server logs for unusual requests that may indicate attempts to exploit this vulnerability, focusing on systems that utilize the vulnerable Forge library (logsource: `webserver`).
