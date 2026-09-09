---
title: Privilege Escalation in PublishPress Capabilities Plugin
slug: 2026-09-publishpress-privilege-escalation
description: The PublishPress Capabilities WordPress plugin (<= 2.50.0) contains a privilege escalation vulnerability that automatically grants 'Editor' users full site-wide capability management permissions without administrative consent.
date: "2026-09-09T08:48:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:publishpress:capabilities:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - PublishPress
products:
  - PublishPress Capabilities – User Role Editor, Access Permissions, User Capabilities, Admin Menus (<= 2.50.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with Editor-level access to elevate their privileges to a site-wide capability manager.
    confidence_band: high
cves:
  - id: CVE-2026-75927
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75927
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade PublishPress Capabilities plugin to version > 2.50.0
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 2.50.0
  hunt_leads:
    - lead: Search WordPress access logs for non-admin accounts performing role management or settings updates
      technique_id: T1068
      data_needed:
        - WordPress activity/audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can manage roles and modify plugin settings via the plugin GUI
  mitigation_plan:
    - priority: immediate
      action: Review and audit user roles for unauthorized changes to capabilities
      owner: SOC
      addresses: CVE-2026-75927
      evidence: Privilege escalation grants manage_capabilities_* permissions
---

The PublishPress Capabilities plugin for WordPress, specifically in versions 2.50.0 and earlier, is vulnerable to an unauthorized privilege escalation flaw. The issue resides within the 'addPluginCapabilities()' function, which executes automatically during the 'admin_init' hook upon plugin activation. This function unilaterally grants the WordPress 'Editor' role fifteen distinct 'manage_capabilities_*' capabilities, such as 'manage_capabilities', 'manage_capabilities_roles', and 'manage_capabilities_settings', without requiring administrator verification or opt-in.

Because these capability assignments are persisted directly into the site's database, an authenticated user already holding the 'Editor' role can gain control over role management and plugin configuration settings. While this does not bypass WordPress's internal 'map_meta_cap' logic to provide full administrative control, it empowers the escalated Editor to manipulate non-system roles, restore role backups, and write arbitrary plugin options prefixed with 'cme_', 'capsman', 'pp_capabilities', or 'presspermit'. This vulnerability is significant for organizations relying on the plugin to restrict user administrative tasks, as it effectively nullifies the separation of duties between Administrators and Editors regarding site capability management.

## Impact

Successful exploitation allows authenticated users with the Editor role to gain unauthorized control over role-based access control (RBAC) configurations and plugin settings. This can lead to the unauthorized creation or deletion of roles, manipulation of non-administrator capabilities, and the modification of sensitive plugin options. This impacts the integrity and availability of access control within the WordPress environment, potentially facilitating further malicious activities by enabling an attacker to maintain elevated, unauthorized permissions within the administrative interface.

## Recommendation

- Upgrade the PublishPress Capabilities plugin to a version beyond 2.50.0 immediately.
- Review WordPress audit logs for any role or capability changes initiated by user accounts assigned the 'Editor' role.
- Audit the 'wp_options' table for modifications to keys prefixed with 'cme_', 'capsman', 'pp_capabilities', or 'presspermit' to identify potential post-exploitation configuration changes.
- Temporarily revoke the 'Editor' role from suspicious accounts until the plugin is patched.
