---
title: Theme My Login Privilege Escalation via Account Takeover
slug: 2026-10-theme-my-login-privilege-escalation
description: An unauthenticated account takeover vulnerability in the Theme My Login WordPress plugin allows attackers to change arbitrary user passwords due to improper identity validation.
date: "2026-10-16T08:24:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:thememylogin:theme_my_login:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - web-application
vendors:
  - Theme My Login
products:
  - Theme My Login (<= 7.2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The Theme My Login plugin for WordPress is vulnerable to privilege escalation via account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-89079
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89079
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Theme My Login plugin to the version containing the fix for CVE-2026-89079
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability in versions up to 7.2.1
  mitigation_plan:
    - priority: immediate
      action: Disable Theme My Login plugin on multi-site WordPress installations until patched
      owner: IT Operations
      addresses: CVE-2026-89079
      evidence: The vulnerability affects multi-site setups in certain configurations
---

The Theme My Login plugin for WordPress, in versions up to and including 7.2.1, contains a critical security vulnerability (CVE-2026-89079) that enables account takeover. The flaw resides in the plugin's password update mechanism, which fails to adequately verify the identity of the user requesting the change. On multi-site WordPress installations with specific configurations, this weakness allows an unauthenticated attacker to supply target user identifiers and successfully reset their passwords without prior authentication. Given the nature of this vulnerability, it poses a high risk of privilege escalation, potentially granting attackers administrative access to the affected WordPress instances. Defenders should treat this as a high-priority update, as successful exploitation results in complete compromise of affected accounts.

## Impact

Successful exploitation of CVE-2026-89079 allows unauthenticated remote attackers to gain unauthorized access to any user account on vulnerable multi-site WordPress installations. This can lead to the total compromise of site administration, unauthorized data access, and potential persistence if an attacker creates or promotes additional accounts. The scope is limited to WordPress installations utilizing the Theme My Login plugin in specific configurations.

## Recommendation

* Immediately update the Theme My Login plugin to the latest patched version available.
* Audit WordPress user activity logs for suspicious password change events, specifically looking for password resets performed for administrative accounts by unknown or unauthenticated sessions.
* Review all user accounts for unauthorized changes to security credentials.
* Disable the affected plugin functionality on multi-site configurations until the software has been updated.
