---
title: WordPress Import and Export Users Plugin Privilege Escalation Vulnerability
slug: 2026-05-wordpress-privesc
description: A privilege escalation vulnerability exists in the Import and export users and customers plugin for WordPress (versions <= 2.0.8) due to an incomplete blocklist allowing authenticated users to gain administrator privileges on subsites within a Multisite network.
date: "2026-05-02T05:16:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - wordpress
  - cloud
vendors:
  - WordPress
products:
  - Import and export users and customers plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7641
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7641
rules:
  - title: WordPress Multisite Privilege Escalation via Profile Update
    description: Detects attempts to exploit CVE-2026-7641 by monitoring POST requests to `/wp-admin/profile.php` with modifications to multisite capability meta keys.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: WordPress User Role Change Detection
    description: Detects suspicious changes to user roles by monitoring WordPress logs for specific keywords.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Import and export users and customers plugin for WordPress, a plugin used to manage user data, is vulnerable to privilege escalation. This vulnerability, identified as CVE-2026-7641, affects all versions of the plugin up to and including 2.0.8. The vulnerability stems from an incomplete blocklist in the `save_extra_user_profile_fields()` function. This function fails to adequately filter meta keys for subsites within a WordPress Multisite network, allowing attackers to manipulate user roles. Successful exploitation allows authenticated attackers with Subscriber-level access or higher to escalate their privileges to Administrator on any subsite within the Multisite network. Exploitation requires the targeted WordPress instance to be part of a Multisite network and have specific settings enabled.

## Attack Chain

1.  An administrator imports a CSV file containing multisite-prefixed capability column headers (e.g., `wp_2_capabilities`) using the affected plugin.
2.  The administrator enables the "Show fields in profile?" option within the plugin settings. This action stores the imported column headers (including the multisite capabilities) in the `acui_columns` option.
3.  A low-privileged user (e.g., Subscriber) authenticates to the WordPress subsite.
4.  The attacker navigates to their user profile page (`/wp-admin/profile.php`). The plugin displays the previously imported multisite capability fields as editable options on the profile page.
5.  The attacker crafts a profile update request, setting the value of the `wp_{subsite_id}_capabilities` meta key to `a:1:{s:13:"administrator";b:1;}` which grants administrator privileges.
6.  The attacker submits the crafted profile update to `/wp-admin/profile.php`.
7.  The `save_extra_user_profile_fields()` function processes the update. Due to the incomplete blocklist, the function fails to prevent the modification of the `wp_{subsite_id}_capabilities` meta key.
8.  The `update_user_meta()` function writes the attacker-controlled value directly to the user's metadata, granting them Administrator privileges on the specified subsite.

## Impact

Successful exploitation of CVE-2026-7641 allows an attacker to gain complete control over a WordPress subsite within a Multisite network. This can lead to unauthorized access to sensitive data, modification of website content, installation of malicious plugins or themes, and potential compromise of the entire Multisite network. Given the widespread use of WordPress and the Import and export users and customers plugin, a successful attack can have significant repercussions for affected organizations.

## Recommendation

*   Upgrade the Import and export users and customers plugin to the latest version to patch CVE-2026-7641.
*   Apply the Sigma rule `WordPress Multisite Privilege Escalation via Profile Update` to detect exploitation attempts against `/wp-admin/profile.php`.
*   Review the `acui_columns` option in the WordPress database to identify any instances where multisite-prefixed capability column headers have been imported, and remove those fields.
*   Monitor WordPress user profile updates for unusual modifications to user capabilities using the `WordPress User Role Change Detection` rule.
