---
title: Privilege Escalation in Eventin WordPress Plugin
slug: 2026-09-eventin-privilege-escalation
description: The Eventin WordPress plugin (<= 4.1.23) contains a vulnerability that allows users with ID 1 to bypass capability checks and escalate privileges to administrator level.
date: "2026-09-15T07:39:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:themefic:eventin:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - plugin-vulnerability
vendors:
  - Themefic
products:
  - Eventin (<= 4.1.23)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Eventin – Event Calendar, Tickets, Registration, Booking & WooCommerce plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.1.23.
    confidence_band: high
cves:
  - id: CVE-2026-75983
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75983
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Eventin to version 4.1.24 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in 4.1.23 and earlier.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Eventin plugin to patch CVE-2026-75983.
      owner: IT Operations
      addresses: CVE-2026-75983
---

The Eventin - Event Calendar, Tickets, Registration, Booking & WooCommerce plugin for WordPress is vulnerable to a privilege escalation flaw (CVE-2026-75983) affecting all versions up to and including 4.1.23. The issue stems from the `PermissionManager::manage_permissions()` function, which is improperly registered as a callback to the WordPress `map_meta_cap` filter. This function unconditionally returns the 'exist' capability for any check performed against user ID 1, regardless of the specific capability requested. 

This vulnerability poses a significant risk to WordPress sites that have implemented security hardening by demoting the default user ID 1 from the Administrator role to a lower-privileged role (e.g., Subscriber). An attacker who gains control of the account associated with user ID 1 can effectively bypass all permission checks, enabling them to perform unauthorized administrative actions such as modifying site settings, promoting users, or installing arbitrary code via the plugin or theme editors. Sites where user ID 1 retains the default Administrator role remain at the same privilege level, as the bypass merely confirms existing administrative rights.

## Impact

Successful exploitation allows an authenticated attacker possessing user ID 1 to achieve full administrative control over the target WordPress instance. This leads to total site takeover, potential data exfiltration, and the ability to execute arbitrary PHP code through administrative interfaces such as the theme or plugin editor. The vulnerability specifically targets environments where administrators have followed hardening practices by demoting the initial user account.

## Recommendation

- Immediately update the Eventin plugin to a version released after 4.1.23 to patch CVE-2026-75983.
- Review all administrative accounts to ensure that user ID 1 is not assigned to a low-privileged account if it is not necessary for operation.
- Audit WordPress user accounts to identify if any account assigned user ID 1 has been granted unexpected roles or if that ID has been compromised.
- Implement file integrity monitoring on the WordPress `/wp-content/plugins/` and `/wp-content/themes/` directories to detect unauthorized code execution attempts following a potential privilege escalation.
