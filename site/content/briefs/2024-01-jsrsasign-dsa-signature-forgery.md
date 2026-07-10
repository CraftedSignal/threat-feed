---
title: jsrsasign DSA Signature Forgery Vulnerability (CVE-2026-4600)
slug: 2024-01-jsrsasign-dsa-signature-forgery
description: The jsrsasign package before version 11.1.1 is vulnerable to cryptographic signature forgery (CVE-2026-4600) due to improper DSA domain-parameter validation, allowing attackers to forge DSA signatures or X.509 certificates, potentially leading to unauthorized access or code execution.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - jsrsasign
  - signature-forgery
  - dsa
  - cve-2026-4600
vendors:
  - jsrsasign
products:
  - jsrsasign
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4600
rules:
  - title: Detect DSA Public Key with Suspicious Parameters
    description: Detects DSA public keys with parameters g=1 and y=1, indicative of CVE-2026-4600 exploitation attempts.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - webserver
      - linux
  - title: Detect DSA Signature Verification with r=1
    description: Detects attempts to verify DSA signatures where the parameter 'r' is set to 1, a common characteristic of CVE-2026-4600 exploits.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-4600, affects jsrsasign versions before 11.1.1. This flaw stems from insufficient validation of DSA domain parameters within the KJUR.crypto.DSA.setPublic function and related DSA/X509 verification processes in src/dsa-2.0.js. The vulnerability allows an attacker to forge DSA signatures or X.509 certificates. By supplying malicious domain parameters (e.g., g=1, y=1, fixed r=1), an attacker can manipulate the verification equation to evaluate as true, irrespective of the actual hash value. This can lead to successful verification of a forged signature by X509.verifySignature(). This poses a significant risk, as it can be exploited to bypass authentication mechanisms or install malicious software that appears to be legitimately signed.

## Attack Chain

1. An attacker crafts a malicious DSA key pair, manipulating the domain parameters g, y, and r to specific values (e.g., g=1, y=1, r=1).
2. The attacker uses this maliciously crafted key to forge a DSA signature for arbitrary data.
3. The forged signature, along with the manipulated DSA public key, is presented to an application using a vulnerable version of jsrsasign.
4. The application calls KJUR.crypto.DSA.setPublic with the attacker-controlled public key, which contains the malicious domain parameters.
5. The application attempts to verify the forged signature using X509.verifySignature().
6. Due to the improper validation of DSA domain parameters, the verification equation evaluates to true regardless of the hash of the signed data.
7. The application incorrectly accepts the forged signature as valid.
8. The attacker gains unauthorized access to resources or executes arbitrary code, relying on the successful verification of the forged signature.

## Impact

Successful exploitation of CVE-2026-4600 can have severe consequences. An attacker can forge digital signatures, potentially allowing them to bypass security controls, impersonate legitimate entities, or distribute malicious software that appears to be trusted. This can lead to widespread compromise, data breaches, and significant reputational damage. The vulnerability impacts any application using the vulnerable jsrsasign library for DSA signature verification, particularly those relying on X.509 certificates for authentication and authorization.

## Recommendation

*   Upgrade the jsrsasign package to version 11.1.1 or later to remediate CVE-2026-4600.
*   Deploy the Sigma rule "Detect DSA Public Key with Suspicious Parameters" to identify attempts to use DSA public keys with g=1 and y=1 in your environment.
*   Monitor web server logs (category: webserver, product: linux) for suspicious requests involving DSA signature verification, particularly those using parameters like g=1, y=1, and r=1.
