---
title: Jsrsasign < 11.1.1 Incorrect Conversion Vulnerability (CVE-2026-4602)
slug: 2026-03-jsrsasign-vuln
description: Jsrsasign versions before 11.1.1 are vulnerable to an incorrect conversion between numeric types vulnerability, where an attacker can force the computation of incorrect modular inverses and break signature verification by calling modPow with a negative exponent.
date: "2026-03-23T06:16:22Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - jsrsasign
  - vulnerability
  - signature-bypass
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4602
  - https://security.snyk.io/vuln/SNYK-JS-JSRSASIGN-15371175
  - https://gist.github.com/Kr0emer/7ecd2be7d17419e4677315ef3758faf5
  - https://github.com/kjur/jsrsasign/commit/5ea1c32bb2aa894b4bd29849839afe4f98728195
rules:
  - title: Detect jsrsasign version usage in package-lock.json
    description: Detects the usage of vulnerable jsrsasign versions in package-lock.json files, indicating potential vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
  - title: Detect jsrsasign version usage in package.json
    description: Detects the usage of vulnerable jsrsasign versions in package.json files, indicating potential vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Jsrsasign is a free open source cryptography library for JavaScript. Versions before 11.1.1 contain an incorrect conversion between numeric types due to improper handling of negative exponents in the `ext/jsbn2.js` file. This vulnerability, identified as CVE-2026-4602, allows an attacker to force the computation of incorrect modular inverses, leading to the potential breakage of signature verification. The vulnerability was reported and patched in March 2026. This could allow an attacker to…
