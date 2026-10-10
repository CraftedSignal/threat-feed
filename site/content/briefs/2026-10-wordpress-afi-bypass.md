---
title: Authentication Bypass in Advanced Form Integration WordPress Plugin
slug: 2026-10-wordpress-afi-bypass
description: CVE-2026-104797 allows unauthenticated attackers to change the passwords of any WordPress user, including administrators, via an unverified profile update action in the Advanced Form Integration plugin.
date: "2026-10-10T05:34:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:advanced_form_integration:connect_forms_to_300_apps:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - authentication-bypass
  - cve-2026-104797
vendors:
  - Advanced Form Integration
products:
  - Advanced Form Integration — Connect Forms to 300+ Apps (<= 2.9.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can leverage a pre-configured Contact Form 7 integration to modify arbitrary user profile fields.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This makes it possible for unauthenticated attackers to change the password of any WordPress user account, including Administrator accounts.
    confidence_band: high
cves:
  - id: CVE-2026-104797
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104797
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Advanced Form Integration to 2.9.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source document indicates 2.9.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Disable Update Profile Field action in plugin settings
      owner: IT Operations
      addresses: CVE-2026-104797
      evidence: Plugin configuration allows exploitation of the vulnerable function
---

The Advanced Form Integration - Connect Forms to 300+ Apps plugin for WordPress (versions 2.9.0 and below) contains a critical authentication bypass vulnerability, identified as CVE-2026-104797. The flaw exists within the `adfoin_ultimatememberac_send_data` function, which is designed to process Ultimate Member "Update Profile Field" actions. The function fails to perform necessary identity verification, ownership checks, or capability checks before updating user profile data. Furthermore, it explicitly bypasses banned-key validation, allowing users to modify sensitive keys, including `user_pass`.

Defenders should note that exploitation is contingent upon a specific configuration: an administrator must have set up a Contact Form 7 integration that maps public form inputs (email, field key, and value) to the Ultimate Member Update Profile Field action. When this condition is met, an unauthenticated attacker can supply a target user's email address and the `user_pass` key to reset that user's password, granting the attacker full administrative access to the WordPress site.

## Impact

Successful exploitation allows unauthenticated attackers to hijack any user account on the affected WordPress site. Because the vulnerability permits the modification of the `user_pass` field, an attacker can target administrative accounts to gain full site control, perform unauthorized data exfiltration, install persistent backdoors, or distribute malicious content through the site.

## Recommendation

- Upgrade the Advanced Form Integration plugin to version 2.9.1 or later immediately.
- Review all configured Contact Form 7 integrations for the Advanced Form Integration plugin to ensure they do not map user-supplied input to sensitive WordPress profile fields, specifically `user_pass`.
- Audit WordPress user accounts and administrative logs for unauthorized password changes or suspicious profile modifications occurring since the initial deployment of the plugin.
- Disable the "Update Profile Field" action in the Advanced Form Integration plugin until the patch is applied.
