---
title: Privilege Escalation in Subscriptions for WooCommerce Plugin
slug: 2026-08-woocommerce-priv-esc
description: The Subscriptions for WooCommerce plugin for WordPress is susceptible to privilege escalation allowing authenticated users with Contributor access to promote themselves to Administrator via insecure meta box handling.
date: "2026-08-01T03:48:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - privilege-escalation
  - web-application
  - cve-2026-15414
vendors:
  - WordPress
products:
  - Subscriptions for WooCommerce (2.0.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Subscriptions for WooCommerce plugin for WordPress is vulnerable to Privilege Escalation.
    confidence_band: high
cves:
  - id: CVE-2026-15414
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15414
---

The Subscriptions for WooCommerce plugin for WordPress (versions 2.0.0 and earlier) contains a critical privilege escalation vulnerability (CVE-2026-15414). The flaw resides in the `save_meta_boxes()` function, which incorrectly handles the `_wps_plan_user_role` meta field during membership plan creation. The plugin relies on client-side `disabled` attributes in the UI to prevent the selection of privileged roles, a control that is trivially bypassed. Furthermore, the backend validation uses `sanitize_key()` and `wp_roles()->is_role()`, both of which permit the 'administrator' role. Because the `wps_membership_plan` post type uses standard post capabilities, any user with permission to edit posts (Contributor or higher) can trigger the `save_meta_boxes()` function. If the Pro companion plugin is active, it processes the injected 'administrator' value in `_wps_plan_user_role` and promotes the attacker via `add_role()`.

## Attack Chain

1. Attacker authenticates as a user with Contributor-level access or higher.
2. Attacker initiates an HTTP POST request to modify or create a `wps_membership_plan` post.
3. Attacker bypasses the UI's `disabled` attribute by intercepting the request or using browser DevTools.
4. Attacker injects the `administrator` value into the `_wps_plan_user_role` meta field within the POST body.
5. The plugin's `save_meta_boxes()` function executes, validating the input with insufficient checks that allow the 'administrator' string.
6. The `_wps_plan_user_role` meta is persisted to the database for the membership plan.
7. The Pro companion plugin monitors membership lifecycle events and reads the malicious meta via `get_post_meta()`.
8. The Pro plugin executes `add_role()` using the attacker-supplied value, promoting the user to Administrator.

## Impact

Successful exploitation results in full administrative control over the WordPress instance. This vulnerability affects all installations using Subscriptions for WooCommerce 2.0.0 or lower where the Pro companion plugin is also installed. An attacker gaining administrative access can execute arbitrary code, modify site content, exfiltrate user data, or deploy persistent backdoors within the WordPress environment.

## Recommendation

Prioritized actions for detection and mitigation:
* Update the Subscriptions for WooCommerce plugin to the latest version once a patch is available.
* Audit existing membership plans for any `_wps_plan_user_role` meta values set to 'administrator' or other unauthorized roles.
* Monitor web server logs for suspicious POST requests targeting `wps_membership_plan` post updates that contain unexpected role parameters.
* Review all user accounts with Administrator privileges for suspicious recent activity or unauthorized creation.
