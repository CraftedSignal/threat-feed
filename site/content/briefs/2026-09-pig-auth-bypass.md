---
title: Authentication Bypass in pig via Password Reset Endpoint
slug: 2026-09-pig-auth-bypass
description: An authentication bypass vulnerability in pig versions prior to 4.1.0 allows remote attackers to perform unauthorized account takeovers by exploiting improper password verification in the /register/password endpoint.
date: "2026-09-15T13:40:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:pig_project:pig:*:*:*:*:*:*:*:*
products:
  - pig (< 4.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.002
    technique_name: Use Alternate Authentication Material
    evidence: Remote attackers can submit a username with an incorrect current password to overwrite any account credential including the admin account and gain full administrative control.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Remote attackers can submit a username with an incorrect current password to overwrite any account credential including the admin account and gain full administrative control.
    confidence_band: high
cves:
  - id: CVE-2026-91995
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91995
rules:
  - title: Detects CVE-2026-91995 Exploitation - Unauthorized Password Reset Attempt
    description: Detects exploitation attempts against the /register/password endpoint of the pig application where password verification is bypassed.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege-escalation
    techniques:
      - T1098
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade pig to version 4.1.0 or later to patch CVE-2026-91995.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-91995 patch requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade pig to version 4.1.0 or later
      owner: IT Operations
      addresses: CVE-2026-91995
      evidence: Source provided version requirements
---

The pig application, in versions prior to 4.1.0, is affected by a critical authentication bypass vulnerability located in the /register/password endpoint. The vulnerability stems from the application discarding the results of the password verification process during the account credential update flow. Consequently, an attacker can supply an arbitrary value as the current password, bypass the validation check, and successfully overwrite the credentials for any user account, including administrative accounts. This flaw provides remote attackers with an unauthenticated path to achieve full administrative control over the affected application. Because the vulnerability allows for complete account takeover, it poses a significant risk to the integrity and confidentiality of the environment hosting the pig service.

## Impact

Successful exploitation allows remote attackers to gain full administrative access to the pig application. This can lead to complete loss of account control, unauthorized access to sensitive application data, and the potential for further lateral movement if the application is integrated with other enterprise systems.

## Recommendation

Prioritized actions for security teams:
- Patch the pig application to version 4.1.0 or later immediately to remediate CVE-2026-91995.
- Review web server access logs for any POST requests directed to the /register/password endpoint that correlate with suspicious administrative account changes or unexpected password resets.
- Audit existing administrative accounts for unauthorized modifications or newly created entries that align with the timeline of potential exploitation.
