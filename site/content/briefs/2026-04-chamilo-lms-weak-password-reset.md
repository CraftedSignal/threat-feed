---
title: Chamilo LMS Weak Password Reset Vulnerability (CVE-2026-33707)
slug: 2026-04-chamilo-lms-weak-password-reset
description: Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3 are vulnerable to a weak password reset mechanism, allowing attackers to compute password reset tokens using only a user's email address due to the use of SHA1 hashing without randomization, expiration, or rate limiting, leading to unauthorized account takeover.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
tags:
  - CVE-2026-33707
  - chamilo
  - lms
  - password-reset
  - credential-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
cves:
  - id: CVE-2026-33707
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33707
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-f27g-66gq-g7v2
ioc_counts:
  email: 1
rules:
  - title: Detect High Volume Password Reset Requests
    description: Detects a high number of password reset requests from the same IP address, which could indicate an attempt to exploit CVE-2026-33707 by brute-forcing email addresses.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
  - title: Detect Password Reset Confirmation Attempts
    description: Detects access to the password reset confirmation page, which is used to finalize the password reset process. This can be an indicator of an attacker trying to exploit the weak password reset.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a widely used learning management system, is susceptible to a critical vulnerability (CVE-2026-33707) affecting versions prior to 1.11.38 and 2.0.0-RC.3. The vulnerability lies within the default password reset mechanism, which generates password reset tokens by applying SHA1 hashing directly to user email addresses. This flawed process lacks essential security measures, including the addition of random salts, token expiration, and rate limiting. An attacker who obtains a target…
