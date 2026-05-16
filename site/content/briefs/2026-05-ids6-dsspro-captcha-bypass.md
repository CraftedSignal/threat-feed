---
title: iDS6 DSSPro Digital Signage System CAPTCHA Bypass Vulnerability (CVE-2020-37228)
slug: 2026-05-ids6-dsspro-captcha-bypass
description: iDS6 DSSPro Digital Signage System 6.2 contains a CAPTCHA security bypass vulnerability (CVE-2020-37228) that allows attackers to bypass authentication by requesting the autoLoginVerifyCode object and performing brute-force attacks against user accounts.
date: "2026-05-16T16:17:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - captcha-bypass
  - credential-access
  - brute-force
vendors:
  - iDS6
products:
  - DSSPro Digital Signage System 6.2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2020-37228
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37228
  - CVE-2020-37228
rules:
  - title: Detect iDS6 DSSPro Captcha Bypass
    description: Detects CVE-2020-37228 exploitation — request to the login endpoint to retrieve the autoLoginVerifyCode object, indicating a CAPTCHA bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
  - title: Detect Multiple Failed Login Attempts After CAPTCHA Bypass
    description: Detects a high number of failed login attempts from the same source IP address after a CAPTCHA bypass attempt, indicating a brute-force attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
rules_count: 2
---

iDS6 DSSPro Digital Signage System version 6.2 is vulnerable to a CAPTCHA security bypass, identified as CVE-2020-37228. This flaw allows unauthenticated attackers to circumvent the CAPTCHA mechanism by requesting the `autoLoginVerifyCode` object. By exploiting this vulnerability, attackers can retrieve valid CAPTCHA codes from the login endpoint and subsequently use them to conduct brute-force attacks against user accounts. The high CVSS score of 9.8 underscores the critical severity of this vulnerability, making it a significant risk for organizations using the affected digital signage system.

## Attack Chain

1.  The attacker identifies an iDS6 DSSPro Digital Signage System 6.2 instance.
2.  The attacker sends a request to the login endpoint to retrieve the `autoLoginVerifyCode` object, bypassing the CAPTCHA.
3.  The system returns a valid CAPTCHA code to the attacker.
4.  The attacker uses the retrieved CAPTCHA code in a series of login attempts.
5.  The attacker inputs a username and attempts various passwords, along with the valid CAPTCHA.
6.  The system validates the CAPTCHA code, allowing the brute-force attack to proceed.
7.  The attacker successfully guesses a valid password for a user account.
8.  The attacker gains unauthorized access to the iDS6 DSSPro Digital Signage System with the compromised account.

## Impact

Successful exploitation of CVE-2020-37228 allows attackers to bypass authentication mechanisms and gain unauthorized access to the iDS6 DSSPro Digital Signage System. This can lead to the compromise of sensitive information, disruption of digital signage operations, and potential further exploitation of the system. Given the high CVSS score, this poses a critical risk.

## Recommendation

*   Apply any available patches or upgrades provided by iDS6 to address CVE-2020-37228 on DSSPro Digital Signage System 6.2.
*   Implement rate limiting on login attempts to mitigate brute-force attacks, in conjunction with the CAPTCHA bypass vulnerability.
*   Deploy the Sigma rule `Detect iDS6 DSSPro Captcha Bypass` to monitor for suspicious requests to the login endpoint with the `autoLoginVerifyCode` object.
*   Review user account access and privileges, and enforce strong password policies to reduce the risk of successful brute-force attacks.
