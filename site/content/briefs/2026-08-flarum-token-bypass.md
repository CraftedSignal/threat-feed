---
title: Password Reset Token Expiry Bypass in Flarum
slug: 2026-08-flarum-token-bypass
description: Flarum versions prior to 1.8.16 are vulnerable to an unauthenticated password reset token expiry bypass, allowing attackers to reuse expired tokens to gain unauthorized account access.
date: "2026-08-05T17:20:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - account-takeover
  - cve-2026-39923
vendors:
  - Flarum
products:
  - Flarum (< 1.8.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The SavePasswordController::handle() method calls PasswordToken::findOrFail() without performing any expiry validation, allowing attackers to bypass the 24-hour token lifetime.
    confidence_band: high
cves:
  - id: CVE-2026-39923
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39923
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Flarum to 1.8.16+
      owner: IT Operations
      due: 48h
      evidence: Vendor vulnerability report for CVE-2026-39923
  mitigation_plan:
    - priority: immediate
      action: Upgrade software
      owner: IT Operations
      addresses: CVE-2026-39923
      evidence: NVD advisory
---

Flarum versions prior to 1.8.16 contain a security flaw in the password reset mechanism. The vulnerability exists within the SavePasswordController::handle() method, which fails to perform server-side validation of token expiration during the processing phase of a password reset. 

Although the platform enforces a 24-hour lifetime for password reset tokens during the initial form rendering process, this check is not re-validated when the submission is processed. Consequently, an unauthenticated attacker can capture or brute-force expired password reset tokens and submit them directly to the reset processing endpoint. Successful exploitation allows the attacker to reset any user account password, resulting in full account takeover and unauthorized authenticated access to the application. This vulnerability presents a high risk for organizations using Flarum for forum management or community hosting.
