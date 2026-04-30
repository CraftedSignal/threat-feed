---
title: Amelia WordPress Plugin IDOR Vulnerability CVE-2026-5465
slug: 2026-04-amelia-idor
description: The Amelia WordPress plugin is vulnerable to an insecure direct object reference, allowing authenticated attackers with Provider-level access or higher to escalate privileges and gain persistence by taking over any WordPress account, including Administrator by manipulating the `externalId` field.
date: "2026-04-07T07:16:24Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - wordpress
  - amelia
  - idor
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5465
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5465
rules:
  - title: Detect Amelia Plugin IDOR Attack
    description: Detects attempts to exploit the IDOR vulnerability (CVE-2026-5465) in the Amelia WordPress plugin by monitoring for suspicious POST requests with modified externalId parameters.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Amelia wp_set_password usage with suspicious externalID
    description: Detects potentially malicious use of wp_set_password function within the Amelia Plugin by non-admin users.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Amelia WordPress plugin, specifically the "Booking for Appointments and Events Calendar", contains an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-5465) in versions up to and including 2.1.3. This flaw resides within the `UpdateProviderCommandHandler` and stems from insufficient validation when a Provider (Employee) user modifies their profile. The critical issue is the ability to manipulate the `externalId` field, which directly corresponds to a WordPress user ID. By injecting an arbitrary `externalId` value during a profile update, an authenticated attacker with Provider-level access or higher can bypass authorization checks. This oversight permits the attacker to execute functions such as `wp_set_password()` and `wp_update_user()` on behalf of any other user, including those with Administrator privileges. This vulnerability allows for complete account takeover, representing a significant risk for organizations utilizing the vulnerable plugin.

## Attack Chain

1. An attacker gains authenticated access to a WordPress instance with the Amelia plugin installed, possessing at least Provider (Employee) level privileges.
2. The attacker navigates to their user profile within the Amelia plugin interface.
3. The attacker intercepts the HTTP request generated when updating their profile using a tool like Burp Suite or browser developer tools.
4. The attacker modifies the `externalId` parameter within the intercepted HTTP request, replacing its original value with the WordPress user ID of the target account they wish to compromise (e.g., the Administrator account, typically user ID 1).
5. The attacker sends the modified HTTP request to the server.
6. Due to the IDOR vulnerability, the `UpdateProviderCommandHandler` fails to validate the manipulated `externalId` value.
7. The Amelia plugin's backend utilizes the attacker-controlled `externalId` to call `wp_set_password()` and/or `wp_update_user()` on the target account.
8. The attacker successfully changes the password or other profile details of the target account, achieving complete account takeover and escalating privileges.

## Impact

Successful exploitation of CVE-2026-5465 allows an attacker with minimal privileges (Provider/Employee role) to compromise any other account on the WordPress instance, including Administrator accounts. This grants the attacker full control over the WordPress site, enabling them to install malicious plugins, modify content, exfiltrate sensitive data, or further compromise the underlying server. The number of potential victims is directly proportional to the number of websites utilizing the vulnerable Amelia plugin. Given the plugin's popularity, a successful mass exploitation could impact thousands of websites across various sectors.

## Recommendation

*   Immediately update the Amelia WordPress plugin to the latest version (greater than 2.1.3) to patch CVE-2026-5465.
*   Monitor web server logs for POST requests to the `/wp-admin/admin-ajax.php` endpoint with the `action` parameter set to `am_update_provider` and a modified `externalId` parameter in the request body. Implement the Sigma rule `Detect Amelia Plugin IDOR Attack` to detect such activity.
*   Implement strong password policies and multi-factor authentication for all WordPress accounts, including those with limited privileges, to mitigate the impact of potential account compromises.
*   Review and audit existing WordPress user accounts and their assigned roles to identify and remove any unnecessary or excessive privileges.
