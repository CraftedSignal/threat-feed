---
title: Privilege Escalation in Nexter Extension WordPress Plugin
slug: 2026-10-nexter-extension-privesc
description: The Nexter Extension plugin for WordPress is vulnerable to privilege escalation (CVE-2026-111114) allowing authenticated users to restore elevated roles due to improper state cleanup during bulk demotions.
date: "2026-10-16T06:26:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:posimyth:nexter_extension:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - vulnerability
vendors:
  - Posimyth
products:
  - Nexter Extension – Security, Performance, Code Snippets & Site Toolkit (<= 4.7.11)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability exists because the /?reset-view handler... performs no nonce or capability check... making it possible for authenticated attackers... to restore the stale stored Administrator role.
    confidence_band: high
cves:
  - id: CVE-2026-111114
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111114
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update Nexter Extension plugin to version > 4.7.11
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111114 vulnerability in Nexter Extension <= 4.7.11
  mitigation_plan:
    - priority: immediate
      action: Identify and clean stale nxtext_view_admin_original_role entries in user meta
      owner: IT Operations
      addresses: CVE-2026-111114
      evidence: Plugin leaves stale administrator meta during bulk demotion
---

The Nexter Extension - Security, Performance, Code Snippets & Site Toolkit plugin for WordPress is vulnerable to privilege escalation in all versions up to and including 4.7.11 (CVE-2026-111114). The vulnerability resides in the role switcher functionality, specifically within the `role_switcher_to_view_admin_as()` function, which lacks appropriate nonce and capability checks.

The flaw is compounded by an inadequate cleanup mechanism in the `profile_update` hook. When a user is demoted from Administrator using the bulk role-change control in `wp-admin/users.php`, the plugin fails to clear the `nxtext_view_admin_original_role` user meta. Because this bypasses the standard `profile_update` hook, the stale administrator role persists in the user profile. Authenticated users who were previously administrators and demoted via this specific bulk path can trigger the `/?reset-view` handler to restore their administrator privileges, granting them unauthorized full access to the WordPress environment.

## Impact

Successful exploitation allows a user with Subscriber-level access or higher to escalate their privileges to Administrator. This impact is contingent on the attacker having previously held Administrator status and having been demoted specifically via the WordPress bulk user management interface. This vulnerability affects any WordPress site utilizing the Nexter Extension plugin (<= 4.7.11).

## Recommendation

* Update the Nexter Extension plugin to a version addressing CVE-2026-111114 immediately.
* Audit the `wp_usermeta` table for suspicious entries in the `nxtext_view_admin_original_role` column, particularly for users who should not currently possess administrative privileges.
* Restrict administrative access to the WordPress bulk user management interface to trusted personnel until the plugin is patched.
