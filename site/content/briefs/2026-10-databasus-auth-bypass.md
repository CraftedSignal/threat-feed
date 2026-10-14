---
title: Authentication Bypass in Databasus via Reset Password Brute-Forcing
slug: 2026-10-databasus-auth-bypass
description: An authentication bypass vulnerability in Databasus versions 3.7.0 through 3.61.0 allows unauthenticated attackers to brute-force six-digit password reset codes due to a lack of rate limiting.
date: "2026-10-14T20:33:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:databasus:databasus:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - authentication-bypass
  - web-application-security
vendors:
  - Databasus
products:
  - Databasus (3.7.0-3.61.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: The lack of rate limiting, or account lockout mechanisms allows unauthenticated attackers to perform brute-force attacks against six-digit password reset codes.
    confidence_band: high
cves:
  - id: CVE-2026-110770
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110770
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Databasus to version 3.62.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability exists in 3.7.0 through 3.61.0
  mitigation_plan:
    - priority: immediate
      action: Enable WAF rate limiting for /api/v1/users/reset-password
      owner: SOC
      addresses: CVE-2026-110770
      evidence: Vulnerability allows brute-forcing due to lack of rate limiting
---

Databasus versions 3.7.0 through 3.61.0 are affected by an authentication bypass vulnerability (CVE-2026-110770) that allows unauthenticated attackers to perform brute-force attacks against the password reset mechanism. The /api/v1/users/reset-password endpoint fails to implement rate limiting, account lockouts, or code invalidation after failed attempts. An attacker can initiate a password reset request for a known email address and subsequently brute-force the six-digit verification code. If successful, the attacker can set a new password for the target account, resulting in full account takeover, including administrative accounts.

## Impact

The vulnerability poses a severe risk to organizational security, as it allows for the takeover of any account, including administrative and service accounts, within a Databasus deployment. Successful exploitation leads to full unauthorized access to database configurations, user data, and potential lateral movement within the network or cloud environment.

## Recommendation

* Upgrade Databasus to version 3.62.0 or later immediately to patch the missing rate limiting logic.
* Monitor web server access logs for high-frequency POST requests to the /api/v1/users/reset-password endpoint originating from single source IP addresses.
* Implement temporary IP-based blocking at the WAF level for any client exceeding a reasonable threshold of requests to the password reset endpoint.
* Audit administrative account activity for suspicious password change events occurring outside of standard maintenance windows.
