---
title: OpenClaw Improper Header Validation Leads to Credential Leakage
slug: 2026-03-openclaw-header-leak
description: OpenClaw before 2026.3.7 is vulnerable to improper header validation in fetchWithSsrFGuard, allowing attackers to intercept sensitive authorization headers via cross-origin redirects.
date: "2026-03-24T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-32913
  - credential-access
  - header-injection
  - openclaw
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32913
  - https://github.com/openclaw/openclaw/commit/46715371b0612a6f9114dffd1466941ac476cef5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-6mgf-v5j7-45cr
  - https://vulncheck.com/advisories/openclaw-mar-custom-authorization-header-leakage-via-cross-origin-redirects
rules:
  - title: Detect Suspicious Header Forwarding
    description: Detects potential header leakage by monitoring for cross-origin redirects where sensitive authorization headers are present in the request.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious URI Redirects
    description: Detects potential exploitation attempts by monitoring for URI requests containing redirects to external or suspicious domains.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a Node.js framework, is susceptible to a critical vulnerability (CVE-2026-32913) affecting versions prior to 2026.3.7. The vulnerability lies in the `fetchWithSsrFGuard` function, which improperly validates headers. This flaw allows attackers to potentially forward custom authorization headers, such as `X-Api-Key` and `Private-Token`, across cross-origin redirects. Successful exploitation enables the interception of sensitive credentials intended for the original, legitimate…
