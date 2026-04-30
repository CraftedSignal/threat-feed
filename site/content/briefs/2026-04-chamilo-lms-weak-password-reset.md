---
title: Chamilo LMS Weak Password Reset Vulnerability (CVE-2026-33707)
slug: 2026-04-chamilo-lms-weak-password-reset
description: Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3 are vulnerable to a weak password reset mechanism, allowing attackers to compute password reset tokens using only a user's email address due to the use of SHA1 hashing without randomization, expiration, or rate limiting, leading to unauthorized account takeover.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
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
iocs:
  - type: email
    value: '[email protected]'
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

Chamilo LMS, a widely used learning management system, is susceptible to a critical vulnerability (CVE-2026-33707) affecting versions prior to 1.11.38 and 2.0.0-RC.3. The vulnerability lies within the default password reset mechanism, which generates password reset tokens by applying SHA1 hashing directly to user email addresses. This flawed process lacks essential security measures, including the addition of random salts, token expiration, and rate limiting. An attacker who obtains a target user's email address can calculate the password reset token and gain unauthorized access to the user's account, bypassing authentication controls. The vulnerability was publicly disclosed in April 2026 and patched in versions 1.11.38 and 2.0.0-RC.3. Organizations using vulnerable versions of Chamilo LMS are at high risk of account compromise.

## Attack Chain

1.  The attacker identifies a valid email address associated with a Chamilo LMS user. This information may be obtained through OSINT or data breaches.
2.  The attacker navigates to the password reset page of the Chamilo LMS instance.
3.  The attacker enters the victim's email address into the password reset form.
4.  The system generates a password reset token by applying SHA1 to the victim's email address without any salt or random component.
5.  The attacker computes the SHA1 hash of the victim's email address offline.
6.  The attacker uses the computed SHA1 hash as the password reset token in a crafted request to the password reset confirmation endpoint.
7.  The Chamilo LMS instance validates the attacker-supplied token against the SHA1 hash of the email.
8.  The attacker sets a new password for the victim's account and gains full access to the compromised account.

## Impact

Successful exploitation of CVE-2026-33707 allows an attacker to take complete control of user accounts within the Chamilo LMS platform. This can lead to data breaches, modification of course content, disruption of educational activities, and potential reputational damage for the affected institution. The lack of rate limiting on password reset requests can allow for automated account takeover attempts affecting many users. Given the widespread use of Chamilo LMS in educational institutions and organizations globally, the potential impact is significant.

## Recommendation

*   Immediately upgrade Chamilo LMS installations to version 1.11.38 or 2.0.0-RC.3 to remediate CVE-2026-33707.
*   Implement rate limiting on password reset requests to mitigate automated attacks attempting to exploit this vulnerability (reference: Overview section).
*   Deploy the Sigma rules below to detect attempts to exploit this vulnerability by monitoring password reset requests (reference: rules section).
*   Monitor web server logs for suspicious password reset requests originating from unusual IPs or with unusually high frequency (reference: rules logsource).
