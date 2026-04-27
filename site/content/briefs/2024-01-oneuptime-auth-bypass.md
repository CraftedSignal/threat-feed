---
title: OneUptime SAML SSO Authentication Bypass Vulnerability (CVE-2026-34840)
slug: 2024-01-oneuptime-auth-bypass
description: OneUptime versions prior to 10.0.42 are vulnerable to an authentication bypass due to improper SAML signature validation, allowing attackers to impersonate users by prepending unsigned assertions.
date: "2026-04-02T20:16:28Z"
severities:
  - critical
tags:
  - CVE-2026-34840
  - saml
  - authentication-bypass
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34840
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34840
rules:
  - title: Detect SAML with Multiple Assertions
    description: Detects SAML authentication requests containing multiple assertions, potentially indicating an authentication bypass attempt in OneUptime.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OneUptime Authentication Bypass Attempt via HTTP Status Code
    description: Detects potential authentication bypass attempts in OneUptime by monitoring for successful HTTP 200 responses to authentication endpoints after a SAML request with multiple assertions, indicating a bypass.
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

OneUptime, an open-source monitoring and observability platform, is vulnerable to an authentication bypass in versions prior to 10.0.42. The vulnerability, identified as CVE-2026-34840, resides in the SAML Single Sign-On (SSO) implementation within the `App/FeatureSet/Identity/Utils/SSO.ts` file. The flawed logic involves a decoupling of signature verification and identity extraction processes. Specifically, the `isSignatureValid()` function checks the signature of the first `<Signature>`…
