---
title: Privilege Escalation Vulnerability in LatePoint Appointment Booking Plugin
slug: 2026-10-latepoint-privesc
description: The LatePoint Appointment Booking plugin for WordPress allows authenticated users with specific capabilities to elevate customer account privileges to administrator via insecure settings management.
date: "2026-10-10T07:50:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:latepoint:latepoint:*:*:*:*:*:wordpress:*:*
vendors:
  - LatePoint
products:
  - Appointment Booking Plugin – LatePoint | Calendar & Scheduling (<= 5.7.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The LatePoint Appointment Booking plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 5.7.3.
    confidence_band: high
cves:
  - id: CVE-2026-104766
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104766
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update LatePoint Appointment Booking plugin to the latest patched version.
      owner: IT Operations
      due: 24h
      evidence: Source document identifies vulnerability in all versions <= 5.7.3.
  mitigation_plan:
    - priority: immediate
      action: Remove 'settings__edit' capability from all non-admin user roles.
      owner: IT Operations
      addresses: CVE-2026-104766
      evidence: Exploitation requires that a WordPress administrator has granted the settings__edit capability to a LatePoint agent or custom role.
---

The Appointment Booking Plugin - LatePoint | Calendar & Scheduling for WordPress (versions 5.7.3 and earlier) contains a critical privilege escalation vulnerability. The flaw exists within the `OsSettingsController::update()` function, which fails to properly validate the `settings` parameters provided by a user during an update request. Furthermore, the `OsSettingsHelper::prepare_value()` method does not enforce a whitelist for the `default_wp_role_for_customer` setting, relying instead solely on client-side UI restrictions that are not validated on the server.

This vulnerability allows an authenticated attacker who has been granted the `settings__edit` capability - such as an agent or a user with a custom role - to modify the default registration role to `administrator`. Consequently, any new user registered through the LatePoint plugin will be assigned full WordPress administrator privileges. This vulnerability is particularly relevant for organizations where delegated administrative permissions are common within the LatePoint platform, as it provides a clear path for lower-privileged users to achieve full site compromise.

## Attack Chain

1. An attacker obtains or is assigned a WordPress user role containing the `settings__edit` capability for the LatePoint plugin.
2. The attacker authenticates to the WordPress administration panel or interacts directly with the plugin's settings update API.
3. The attacker crafts a request to the `OsSettingsController::update()` handler.
4. The attacker injects the `default_wp_role_for_customer` parameter with the value `administrator` into the `settings` array of the update request.
5. The server-side code fails to validate the input against an allowlist, accepting the malicious value.
6. The `OsSettingsHelper::prepare_value()` method persists the new, unauthorized default role configuration to the database.
7. A new customer registers for an account via the LatePoint public-facing booking flow.
8. WordPress creates the new customer account using the attacker-modified default role, granting the new account administrative access.

## Impact

Successful exploitation allows for the creation of unauthorized WordPress administrator accounts, leading to full site takeover, data exfiltration, and potential remote code execution on the underlying server. This affects any WordPress site running LatePoint version 5.7.3 or earlier that utilizes delegated role management for plugin settings.

## Recommendation

1. Update the LatePoint Appointment Booking plugin to a version released after 5.7.3 that incorporates server-side role validation.
2. Audit all existing WordPress user roles and ensure that the `settings__edit` capability is restricted to trusted, verified administrators only.
3. Implement WAF rules to monitor for unusual `POST` requests to WordPress endpoints associated with the LatePoint settings controller that contain parameters referencing `default_wp_role_for_customer`.
4. Regularly review the `wp_users` and `wp_usermeta` tables for any newly created accounts with the administrator role to identify potential abuse.
