---
title: Unauthenticated Account Takeover in MacCMS via Password Recovery Rate Limiting Bypass
slug: 2026-10-maccms-password-reset-bypass
description: MacCMS versions v10 through 2026.1000.4056 are vulnerable to an unauthenticated account takeover via brute-force exploitation of the password recovery function.
date: "2026-10-15T22:50:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:maccms:maccms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - account-takeover
  - vulnerability
  - cve-2026-111356
vendors:
  - MacCMS
products:
  - MacCMS (v10 through 2026.1000.4056)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: An unauthenticated attacker can exploit this flaw by brute-forcing the 'findpass_reset' function to overwrite a user's password.
    confidence_band: high
cves:
  - id: CVE-2026-111356
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111356
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review webserver logs for excessive requests to /findpass_reset
      owner: SOC
      due: 24h
      evidence: Source description of brute-force mechanism
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rate limiting for /findpass_reset
      owner: IT Operations
      addresses: CVE-2026-111356
      evidence: Lack of rate limiting in vulnerable product
---

MacCMS versions v10 through 2026.1000.4056 contain a critical vulnerability in the password recovery mechanism that fails to enforce rate limiting on six-digit recovery codes. This flaw allows an unauthenticated attacker to abuse the 'findpass_reset' function by systematically brute-forcing the verification code required to reset a user's password. An attacker requires only the target's associated email address or phone number to initiate the recovery workflow. Once the correct six-digit code is guessed, the attacker can overwrite the member's existing password, leading to complete account takeover. This vulnerability is particularly impactful in multi-user environments where member account security is essential.

## Impact

The vulnerability poses a high risk of unauthorized account access, potentially leading to data exfiltration, account impersonation, and unauthorized administrative actions within the MacCMS application. Given the ubiquity of CMS platforms, any site running vulnerable versions is susceptible to automated account takeover campaigns.

## Recommendation

* Monitor web access logs for high-frequency POST requests to the 'findpass_reset' endpoint from a single source IP address, which may indicate automated brute-force attempts.
* Implement rate limiting or account lockout policies at the web application firewall (WAF) or web server level for the password recovery module.
* Upgrade MacCMS to a patched version beyond 2026.1000.4056 as soon as the vendor provides a remediation.
* Audit user account logs for suspicious password resets that do not correspond with user-initiated activity.
