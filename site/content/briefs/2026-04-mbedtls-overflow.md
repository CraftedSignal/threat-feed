---
title: Mbed TLS FFDH Public Key Export Buffer Overflow
slug: 2026-04-mbedtls-overflow
description: A buffer overflow vulnerability (CVE-2026-34875) exists in Mbed TLS through 3.6.5 and TF-PSA-Crypto 1.0.0 during public key export for FFDH keys, potentially leading to code execution or denial of service.
date: "2026-04-01T18:16:31Z"
severities:
  - critical
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

A critical buffer overflow vulnerability has been identified in Mbed TLS, a widely used open-source cryptographic library. Specifically, CVE-2026-34875 affects Mbed TLS versions up to 3.6.5 and TF-PSA-Crypto 1.0.0. The vulnerability is triggered during the export of public keys associated with Finite Field Diffie-Hellman (FFDH) algorithms. This flaw can be exploited by an attacker to overwrite memory buffers, potentially leading to arbitrary code execution or a denial-of-service condition…
