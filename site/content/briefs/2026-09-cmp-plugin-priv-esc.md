---
title: Privilege Escalation in CMP - Coming Soon & Maintenance Plugin for WordPress
slug: 2026-09-cmp-plugin-priv-esc
description: The CMP - Coming Soon & Maintenance Plugin is vulnerable to privilege escalation due to an unauthenticated AJAX setting import that allows authenticated editors to modify arbitrary site options.
date: "2026-09-22T06:33:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:niteothemes:cmp_coming_soon_maintenance_plugin:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application
  - cms
vendors:
  - NiteoThemes
products:
  - CMP – Coming Soon & Maintenance Plugin (<= 4.1.17)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Editor-level access and above, to update arbitrary options on the WordPress site.
    confidence_band: high
cves:
  - id: CVE-2026-12470
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12470
rules:
  - title: Detects CVE-2026-12470 Exploitation - Unauthorized Plugin Settings Import
    description: Detects exploitation of CVE-2026-12470 by monitoring for AJAX calls to the CMP plugin import settings action.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade CMP - Coming Soon & Maintenance Plugin to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-12470 vulnerability in versions 4.1.17 and below
  hunt_leads:
    - lead: Audit site options for modified 'default_role' or 'users_can_register'
      technique_id: T1068
      data_needed:
        - WordPress database audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker goal is to modify arbitrary site options
  mitigation_plan:
    - priority: immediate
      action: Patch plugin to version > 4.1.17
      owner: IT Operations
      addresses: CVE-2026-12470
      evidence: NVD vulnerability disclosure
---

The CMP - Coming Soon & Maintenance Plugin by NiteoThemes for WordPress is susceptible to an unauthenticated privilege escalation vulnerability tracked as CVE-2026-12470. The vulnerability exists within the 'cmp_ajax_import_settings' AJAX action, which fails to perform necessary capability checks before processing user-supplied data. This allows an authenticated user with Editor-level access or higher to perform unauthorized modifications to the WordPress site's configuration. By manipulating global options, such as the default user role and registration settings, an attacker can elevate their own privileges or create new administrative accounts, ultimately gaining full control over the affected WordPress installation. This issue impacts all plugin versions up to and including 4.1.17.

## Attack Chain

1. Attacker obtains valid credentials for an account with Editor-level permissions on the target WordPress site.
2. Attacker authenticates to the WordPress dashboard using the compromised credentials.
3. Attacker identifies that the CMP plugin is installed and active on the site.
4. Attacker crafts a malicious HTTP POST request targeting the 'admin-ajax.php' endpoint with the 'cmp_ajax_import_settings' action.
5. The request body includes JSON-encoded payload values designed to modify core 'wp_options' table entries.
6. The plugin processes the request without validating the user's capability, updating the site settings to enable 'users_can_register' and setting the 'default_role' to 'administrator'.
7. Attacker navigates to the public registration page to create a new user account, which is automatically assigned the administrator role upon creation.
8. Attacker logs in with the newly created administrator account to achieve full site takeover.

## Impact

Successful exploitation of CVE-2026-12470 results in total compromise of the affected WordPress site. An attacker can gain administrative access, potentially leading to the installation of malicious plugins, backdoored themes, data exfiltration, or the defacement of the website. Any site running the CMP plugin up to version 4.1.17 is considered at high risk of unauthorized administrative account creation.

## Recommendation

Prioritize the immediate update of the CMP - Coming Soon & Maintenance Plugin to a patched version beyond 4.1.17 as provided by NiteoThemes.

For security operations teams:
- Monitor 'wp-admin/admin-ajax.php' access logs for POST requests containing 'cmp_ajax_import_settings' that originate from non-administrative accounts.
- Audit the 'wp_options' table for sudden changes to the 'default_role' and 'users_can_register' keys.
- Review all administrative accounts created recently to ensure they are legitimate.
