---
title: Forge Ed25519 Signature Forgery Vulnerability
slug: 2026-09-forge-ed25519-forgery
description: Forge is vulnerable to signature forgery in Ed25519 due to a missing check that S < L, allowing non-canonical signatures and potentially bypassing authentication/authorization logic, affecting versions before 1.4.0.
date: "2026-03-26T22:08:55Z"
severities:
  - high
tags:
  - ed25519
  - signature-forgery
  - forge
  - javascript
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-q67f-28xg-22rw
  - https://datatracker.ietf.org/doc/html/rfc8032#section-8.4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33895
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25793
  - https://nvd.nist.gov/vuln/detail/CVE-2022-35961
rules:
  - title: Detect Forged Ed25519 Signatures via Modified S Value
    description: Detects potential attempts to use non-canonical Ed25519 signatures where the 'S' value has been manipulated.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - application
      - forge
  - title: Detect Ed25519 Signature Verification with Forge Library
    description: Detects the usage of the Forge library for Ed25519 signature verification, which might be vulnerable to CVE-2026-33895.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - application
      - forge
rules_count: 2
---

The Forge library, a popular JavaScript cryptography toolkit, exhibits a signature forgery vulnerability in its Ed25519 implementation. Specifically, the verification process lacks a critical check to ensure that the scalar 'S' is less than the group order 'L' (S < L). This omission enables the acceptance of non-canonical signatures, effectively forging signatures. This vulnerability affects Forge versions prior to 1.4.0. An attacker could exploit this flaw to bypass security mechanisms that…
