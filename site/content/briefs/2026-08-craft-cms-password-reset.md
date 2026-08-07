---
title: Arbitrary Password Reset Vulnerability in Craft CMS
slug: 2026-08-craft-cms-password-reset
description: An insecure mass-assignment vulnerability in the Craft CMS user element save action allows authenticated users with specific permissions to modify passwords without requiring the current password or elevated verification.
date: "2026-08-06T21:29:10Z"
lastmod: "2026-08-07T15:30:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - cms
  - web-application
  - authentication-bypass
  - cve-2024-45398
vendors:
  - Craft CMS
products:
  - Craft CMS (5.x)
  - Craft CMS (4.x)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.001
    technique_name: Abuse Elevation Control Mechanism
    evidence: The vulnerability exists in the elements/save action when saving a User element... bypassing the dedicated users/set-password action that enforces elevated session verification.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.002
    technique_name: 'Valid Accounts: Domain Accounts'
    evidence: An attacker with any authenticated session (whether it is hijacked or a normal / low-privileged user) can change their own password, and potentially take over administrator accounts.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated remote code execution issue in the control panel element-search condition handling.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: In the confirmed local lab, this led to command execution as the PHP/web user.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who obtains one successful passkey login request body can replay it to create additional authenticated Craft sessions for that user.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-265m-7826-wjqm
  - https://github.com/advisories/GHSA-wg23-69c2-gjc8
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Craft CMS to version 5.10.8
      owner: IT Operations
      due: 24h
      evidence: 'Affected Packages: composer/craftcms/cms (vulnerable: >= 5.0.0-RC1, < 5.10.8)'
  mitigation_plan:
    - priority: immediate
      action: Revoke Edit users permissions from non-administrative users
      owner: IT Operations
      addresses: Account takeover exploitation vector
      evidence: Users with Edit users permission can change any user’s password, including administrators.
updates:
  - at: "2026-08-06T21:29:25Z"
    level: L2
    summary: added coverage for Craft CMS (4.x) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-265m-7826-wjqm
  - at: "2026-08-07T15:30:17Z"
    level: L2
    summary: added coverage for Craft CMS (5.x)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-wg23-69c2-gjc8
---

Craft CMS versions 5.0.0-RC1 through 5.10.7 contain an insecure mass-assignment vulnerability in the user element save mechanism. The vulnerability resides in the `elements/save` action, where the `newPassword` field is processed by the `UserPasswordValidator` without proper scenario-based restrictions. 

Normally, password changes in Craft CMS are gated by the `users/set-password` action, which enforces elevated session verification and requires the user to provide their current password. Because the `newPassword` field is mass-assignable during the generic `elements/save` flow, an attacker with at least "Edit users" permissions can bypass these security controls. This flaw allows an authenticated user to change their own password without verification or, more critically, allows a user with "Edit users" access to overwrite the password of any other user, including those with administrative privileges. This vulnerability impacts all installations running Craft CMS 5.x prior to version 5.10.8.

## Impact

Successful exploitation allows for complete administrative account takeover by any authenticated user assigned the "Edit users" permission. This impacts organizations relying on Craft CMS for content management by enabling unauthorized access to the control panel, potentially leading to unauthorized content modification, data exfiltration, or further system compromise.

## Recommendation

- Upgrade all Craft CMS installations to version 5.10.8 or later immediately to apply the patch for the insecure mass-assignment of the `newPassword` field.
- Audit the "Edit users" permission across all user accounts in the Craft CMS control panel to identify and revoke the privilege from any account that does not explicitly require it.
- Review access logs for the `elements/save` endpoint to identify potential abuse by users with "Edit users" privileges.
