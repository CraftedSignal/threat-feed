---
title: Botan SM2 Decryption Heap Over-read Vulnerability (CVE-2026-32877)
slug: 2026-03-botan-sm2-heap-overread
description: Botan C++ cryptography library versions 2.3.0 before 3.11.0 are vulnerable to a heap over-read during SM2 decryption due to insufficient validation of the authentication code length, potentially leading to crashes or undefined behavior.
date: "2026-03-30T21:17:09Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - vulnerability
  - heap-overread
  - botan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-32877
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32877
  - https://github.com/randombit/botan/security/advisories/GHSA-7jj6-4r42-w9h6
ioc_counts:
  email: 2
rules:
  - title: Detect Process Loading Vulnerable Botan Library
    description: Detects processes loading a vulnerable version of the Botan library (2.3.0 - 3.10.x)
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - image_load
      - windows
  - title: Detect process using vulnerable botan library on Linux
    description: Detects processes loading a vulnerable version of the Botan library (2.3.0 - 3.10.x) on linux systems
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - image_load
      - linux
rules_count: 2
---

Botan is a C++ cryptography library. A vulnerability exists in versions 2.3.0 to prior to 3.11.0 related to SM2 decryption. The flaw lies in the insufficient validation of the authentication code value (C3) length before comparison. An invalid ciphertext can trigger a heap over-read of up to 31 bytes, potentially causing a crash or other undefined behavior. This vulnerability, identified as CVE-2026-32877, can be exploited if the application using the library processes attacker-controlled…
