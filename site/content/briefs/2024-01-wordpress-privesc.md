---
title: WordPress Custom Role Manager Plugin Privilege Escalation via CVE-2026-7106
slug: 2024-01-wordpress-privesc
description: Highland Software's Custom Role Manager plugin for WordPress, versions 1.0.0 and earlier, contains a privilege escalation vulnerability (CVE-2026-7106) that allows authenticated users with subscriber-level access to modify user roles due to insufficient authorization checks in the hscrm_save_user_roles() function.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - wordpress
  - cve
vendors:
  - Highland Software
products:
  - Custom Role Manager plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7106
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7106
rules:
  - title: Detect Suspicious WordPress Role Updates
    description: Detects attempts to modify user roles by low-privileged accounts in WordPress, potentially indicating privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect direct access of hscrm_save_user_roles() function
    description: Detects unauthorized access to the hscrm_save_user_roles() function, which is indicative of a privilege escalation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Highland Software Custom Role Manager plugin, versions up to and including 1.0.0, is vulnerable to privilege escalation. The vulnerability, identified as CVE-2026-7106, stems from a lack of sufficient authorization checks within the `hscrm_save_user_roles()` function. This function is accessible to any authenticated user via the `personal_options_update` action. This allows an attacker with minimal privileges (subscriber level or higher) to potentially elevate their own privileges or those of other users by manipulating user roles through the profile update form. Successful exploitation grants attackers the ability to perform actions reserved for higher-level administrators, potentially leading to complete site compromise.

## Attack Chain

1. An attacker obtains valid credentials for a WordPress user account with at least subscriber-level privileges.
2. The attacker authenticates to the WordPress site using their credentials.
3. The attacker accesses their user profile page, typically located at `/wp-admin/profile.php`.
4. The attacker crafts a malicious HTTP request targeting the `personal_options_update` action, modifying the `wp_capabilities` user meta field. The request is designed to bypass the insufficient authorization checks in the `hscrm_save_user_roles()` function.
5. The crafted request is submitted through the profile update form. This likely involves intercepting and modifying the POST request sent when the user clicks the "Update Profile" button.
6. The `hscrm_save_user_roles()` function is triggered, and due to the missing authorization checks, the attacker's modified user roles are saved to the database.
7. The attacker's account now possesses elevated privileges, such as administrator or editor roles, depending on the attacker's goal and the payload in the malicious request.

## Impact

Successful exploitation of CVE-2026-7106 allows attackers with minimal privileges to gain administrative control over the WordPress site. This can lead to a variety of malicious activities, including defacement, malware injection, data theft, and denial of service. Given the widespread use of WordPress, this vulnerability poses a significant risk to websites using the affected plugin. A successful attack can result in complete compromise of the affected website.

## Recommendation

*   Upgrade the Highland Software Custom Role Manager plugin to a patched version that addresses CVE-2026-7106.
*   Monitor WordPress access logs for suspicious POST requests to `/wp-admin/profile.php` targeting the `personal_options_update` action to detect exploitation attempts.
*   Deploy the Sigma rule `Detect Suspicious WordPress Role Updates` to identify attempts to modify user roles from subscriber-level accounts.
*   Review user roles and permissions regularly to identify and remediate any unauthorized privilege escalations.
