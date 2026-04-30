---
title: Mbed TLS FFDH Public Key Export Buffer Overflow
slug: 2026-04-mbedtls-overflow
description: A buffer overflow vulnerability (CVE-2026-34875) exists in Mbed TLS through 3.6.5 and TF-PSA-Crypto 1.0.0 during public key export for FFDH keys, potentially leading to code execution or denial of service.
date: "2026-04-01T18:16:31Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - buffer-overflow
  - mbedtls
  - crypto
  - cve-2026-34875
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-34875
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34875
  - https://mbed-tls.readthedocs.io/en/latest/security-advisories/
  - https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-03-ffdh-buffer-overflow/
rules:
  - title: Detect MbedTLS FFDH Public Key Export
    description: Detects potential exploitation attempts of the Mbed TLS FFDH public key export buffer overflow by monitoring memory writes to Mbed TLS processes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect MbedTLS FFDH Public Key Export - Linux
    description: Detects potential exploitation attempts of the Mbed TLS FFDH public key export buffer overflow by monitoring memory writes to Mbed TLS processes on Linux.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical buffer overflow vulnerability has been identified in Mbed TLS, a widely used open-source cryptographic library. Specifically, CVE-2026-34875 affects Mbed TLS versions up to 3.6.5 and TF-PSA-Crypto 1.0.0. The vulnerability is triggered during the export of public keys associated with Finite Field Diffie-Hellman (FFDH) algorithms. This flaw can be exploited by an attacker to overwrite memory buffers, potentially leading to arbitrary code execution or a denial-of-service condition. Given the prevalence of Mbed TLS in embedded systems and other security-sensitive applications, this vulnerability poses a significant risk to a wide range of devices and services. Defenders should prioritize patching and mitigation efforts to prevent potential exploitation. The vulnerability was published on 2026-04-01.

## Attack Chain

1.  Attacker identifies a system using a vulnerable version of Mbed TLS (<= 3.6.5) or TF-PSA-Crypto (1.0.0).
2.  Attacker crafts a malicious request that triggers the FFDH public key export function.
3.  The vulnerable function fails to properly validate the size of the buffer used to store the exported public key.
4.  The application attempts to copy the public key data into the undersized buffer.
5.  A buffer overflow occurs, overwriting adjacent memory regions.
6.  The attacker gains control of program execution by overwriting critical data structures or function pointers.
7.  The attacker executes arbitrary code on the target system.
8.  The attacker achieves their final objective, such as gaining unauthorized access, stealing sensitive data, or causing a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-34875 can lead to a variety of severe consequences. The most critical outcome is arbitrary code execution, allowing attackers to gain complete control over the affected system. This could result in the theft of sensitive data, installation of malware, or disruption of critical services. Even without achieving code execution, the buffer overflow can cause a denial-of-service condition, rendering the system unusable. The wide adoption of Mbed TLS means that this vulnerability has the potential to impact numerous devices and applications across various sectors.

## Recommendation

*   Upgrade Mbed TLS to a patched version (later than 3.6.5) or TF-PSA-Crypto to a version that includes the fix for CVE-2026-34875.
*   Apply input validation to any data that is used in the FFDH public key export functionality as a short-term workaround.
*   Deploy the provided Sigma rule `Detect_MbedTLS_FFDH_Public_Key_Export` to identify potential exploitation attempts by monitoring process memory writes in Mbed TLS processes.
*   Monitor web server logs for anomalies in requests related to TLS key exchange, in combination with MbedTLS to catch abnormal activity.
