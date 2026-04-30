---
title: Jsrsasign Infinite Loop Vulnerability (CVE-2026-4598)
slug: 2026-03-jsrsasign-infinite-loop
description: Jsrsasign versions before 11.1.1 are vulnerable to an infinite loop via the bnModInverse function when processing zero or negative inputs, potentially leading to a denial of service.
date: "2026-03-23T06:16:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - javascript
  - node.js
  - jsrsasign
  - vulnerability
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4598
  - https://security.snyk.io/vuln/SNYK-JS-JSRSASIGN-15370938
  - https://github.com/kjur/jsrsasign/commit/ca5b027240287a1e71fe63019fc4400332594323
rules:
  - title: Detect Jsrsasign ModInverse Zero Input
    description: Detects suspicious calls to jsrsasign's bnModInverse function with zero or negative inputs, indicative of CVE-2026-4598 exploitation.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Jsrsasign ModInverse Negative Input
    description: Detects suspicious calls to jsrsasign's bnModInverse function with negative inputs, indicative of CVE-2026-4598 exploitation.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The jsrsasign library, a popular JavaScript library for implementing cryptography standards, is susceptible to a denial-of-service vulnerability. Specifically, versions prior to 11.1.1 are vulnerable to CVE-2026-4598, where the `bnModInverse` function within `ext/jsbn2.js` can enter an infinite loop when processing zero or negative inputs to the `BigInteger.modInverse` function. An attacker can exploit this by providing maliciously crafted values (e.g., `modInverse(0, m)` or `modInverse(-1…
