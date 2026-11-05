---
brief_id: brief-2026-11-05-givewp-privilege-escalation
event_id: brief-2026-11-05-givewp-privilege-escalation
revision: 1
activity_at: "2026-11-05T06:28:31Z"
title: 'GiveWP: Privilege escalation vulnerability (CVE-2026-118193)'
slug: 2026-11-givewp-privilege-escalation
description: The GiveWP WordPress plugin (versions 4.19.1 and earlier) contains a privilege escalation flaw allowing attackers with administrative settings capabilities to assign arbitrary WordPress roles to new donor accounts.
date: "2026-11-05T06:28:31Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:givewp:givewp:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application-security
vendors:
  - GiveWP
products:
  - GiveWP – Donation Plugin and Fundraising Platform (<= 4.19.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.19.1
    confidence_band: high
cves:
  - id: CVE-2026-118193
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118193
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update the GiveWP plugin to a version above 4.19.1.
      owner: IT Operations
      due: 48h
      evidence: Vulnerable in all versions up to, and including, 4.19.1.
  hunt_leads:
    - lead: Monitor for suspicious use of the give_core_settings_import_callback AJAX handler.
      technique_id: T1068
      data_needed:
        - WordPress access logs
        - Application audit logs for plugin setting changes
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The give_core_settings_import_callback AJAX handler writes imported JSON directly into the give_settings option via update_option without invoking the sanitize filter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GiveWP - Donation Plugin to version 4.19.2 or higher.
      owner: IT Operations
      addresses: CVE-2026-118193
      evidence: Patch required for versions <= 4.19.1.
---

GiveWP versions 4.19.1 and earlier are vulnerable to privilege escalation (CVE-2026-118193). The vulnerability stems from insufficient sanitization of the `donor_default_user_role` parameter within the plugin settings. Authenticated users with the `manage_give_settings` capability can exploit the `give_core_settings_import_callback` AJAX handler to bypass role allowlists, potentially assigning the Administrator role to new donor registrations. While direct setting modification attempts to block the Administrator role, the import mechanism fails to invoke the necessary sanitization filters.

## Impact

Successful exploitation allows an authenticated user with restricted administrative privileges (GiveWP Manager) to escalate the privileges of newly created donor accounts, potentially resulting in full administrative compromise of the WordPress installation.

## Recommendation

- Update the GiveWP - Donation Plugin and Fundraising Platform to a version strictly newer than 4.19.1.
- Audit existing donor registration settings and verify that the `donor_default_user_role` option is set to a restricted, non-privileged role.
- Review WordPress user accounts for unexpected administrative privileges or unauthorized account creations originating from the GiveWP platform.
