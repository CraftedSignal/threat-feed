---
title: jsrsasign DSA Signing Vulnerability (CVE-2026-4601)
slug: 2026-03-jsrsasign-dsa
description: jsrsasign versions before 11.1.1 are vulnerable to a missing cryptographic step in the DSA signing implementation, allowing an attacker to recover the private key by manipulating the signature generation process.
date: "2026-03-23T06:16:21Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - jsrsasign
  - dsa
  - missing-cryptographic-step
  - CVE-2026-4601
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4601
  - https://security.snyk.io/vuln/SNYK-JS-JSRSASIGN-15370941
  - https://github.com/kjur/jsrsasign/commit/0710e392ec35de697ce11e4219c988ba2b5fe0eb
  - https://github.com/kjur/jsrsasign/pull/645
  - https://gist.github.com/Kr0emer/93789fe6efe5519db9692d4ad1dad586
rules:
  - title: Detect jsrsasign DSA Vulnerability Attempt via User-Agent
    description: Detects attempts to exploit the jsrsasign DSA vulnerability (CVE-2026-4601) by looking for specific patterns in the User-Agent header.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect jsrsasign DSA Vulnerability Attempt via HTTP Request
    description: Detects attempts to exploit the jsrsasign DSA vulnerability (CVE-2026-4601) by looking for specific patterns in the HTTP request.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in jsrsasign versions prior to 11.1.1, specifically within the `KJUR.crypto.DSA.signWithMessageHash` function used for DSA signing. This flaw, identified as CVE-2026-4601, stems from a missing cryptographic step during signature generation. An attacker can exploit this by manipulating the process to force either the 'r' or 's' component of the signature to be zero. When this occurs, the library generates an invalid signature without retry, which then allows the attacker…
