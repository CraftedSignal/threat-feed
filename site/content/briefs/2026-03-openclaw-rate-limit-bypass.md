---
title: OpenClaw Webhook Rate Limit Bypass Vulnerability (CVE-2026-34505)
slug: 2026-03-openclaw-rate-limit-bypass
description: OpenClaw before 2026.3.12 applies rate limiting only after successful webhook authentication, allowing attackers to bypass rate limits and brute-force webhook secrets leading to forged webhook submission.
date: "2026-03-31T12:16:30Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - rate-limiting
  - brute-force
  - webhook
  - cve-2026-34505
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2026-34505
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34505
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-5m9r-p9g7-679c
  - https://www.vulncheck.com/advisories/openclaw-webhook-rate-limiting-bypass-via-pre-authentication-secret-validation
ioc_counts:
  email: 1
rules:
  - title: Detect Excessive Webhook Authentication Failures
    description: Detects excessive failed authentication attempts to webhook endpoints, potentially indicating a brute-force attack against OpenClaw (CVE-2026-34505).
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
      - linux
  - title: Detect Successful Webhook Authentication Followed by Data Submission
    description: Detects a successful webhook authentication (200 OK) followed shortly by a data submission (200 OK or 204 No Content) to the same webhook endpoint, potentially indicating a malicious webhook submission after a successful brute-force (CVE-2026-34505).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.12 are vulnerable to a rate-limiting bypass (CVE-2026-34505). The vulnerability exists because rate limiting is only applied after successful webhook authentication. This design flaw enables attackers to send numerous authentication requests with incorrect secrets without triggering rate limits. The vulnerability was reported on March 31, 2026. Successful exploitation allows attackers to systematically guess webhook secrets and subsequently submit forged…
