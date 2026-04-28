---
title: Riaxe Product Customizer WordPress Plugin Privilege Escalation Vulnerability (CVE-2026-3596)
slug: 2026-04-wordpress-privesc
description: The Riaxe Product Customizer plugin for WordPress is vulnerable to privilege escalation, allowing unauthenticated attackers to update arbitrary WordPress options via a publicly accessible AJAX endpoint and escalate privileges to administrator.
date: "2026-04-16T06:16:15Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - wordpress
  - privilege-escalation
  - cve-2026-3596
  - plugin
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-3596
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3596
rules:
  - title: Detect Riaxe Product Customizer Privilege Escalation Attempt
    description: Detects attempts to exploit the privilege escalation vulnerability (CVE-2026-3596) in the Riaxe Product Customizer plugin by monitoring POST requests to admin-ajax.php with the install-imprint action.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1548.001
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized User Registration After CVE-2026-3596 Exploitation
    description: Detects potentially unauthorized user registration events following exploitation of the Riaxe Product Customizer vulnerability. This assumes that attackers will enable user registration to create an admin account.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1548.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Riaxe Product Customizer plugin for WordPress, versions 2.1.2 and earlier, contains a critical privilege escalation vulnerability (CVE-2026-3596). This flaw stems from an unauthenticated AJAX action, 'wp_ajax_nopriv_install-imprint', which is improperly secured. The corresponding function, `ink_pd_add_option()`, allows unauthenticated users to modify arbitrary WordPress options by sending POST requests. There are no nonce checks, capability checks, or input validation performed on the 'option' and 'opt_value' parameters, making it trivial to manipulate sensitive site settings. Successful exploitation allows attackers to grant themselves administrative privileges. This vulnerability poses a significant risk to any WordPress site using the affected plugin.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using a vulnerable version of the Riaxe Product Customizer plugin (<= 2.1.2).
2. The attacker crafts a malicious HTTP POST request targeting the `/wp-admin/admin-ajax.php` endpoint.
3. The POST request includes the `action` parameter set to `install-imprint`, triggering the vulnerable AJAX action `wp_ajax_nopriv_install-imprint`.
4. The attacker sets the `option` parameter to `default_role` and the `opt_value` parameter to `administrator` within the POST request. This will change the default user role to administrator.
5. The attacker sets the `option` parameter to `users_can_register` and the `opt_value` parameter to `1` within the POST request. This enables user registration on the WordPress site.
6. The `ink_pd_add_option()` function executes, calling `delete_option()` and `add_option()` with the attacker-supplied values, effectively updating the WordPress options table.
7. The attacker registers a new user account on the WordPress site.
8. Because user registration is enabled and the default user role is set to administrator, the attacker's new account is granted administrator privileges, allowing full control over the WordPress site.

## Impact

Successful exploitation of CVE-2026-3596 allows unauthenticated attackers to gain complete control over a vulnerable WordPress website. This can lead to website defacement, data theft, malware distribution, and denial of service. Given the widespread use of WordPress, this vulnerability has the potential to affect a large number of websites across various sectors. A successful attack would result in the attacker having the same access as the original website administrator.

## Recommendation

*   Immediately remove the Riaxe Product Customizer plugin from WordPress installations if it is present. This will eliminate the attack vector (plugin removal).
*   Monitor web server logs (category: `webserver`, product: `linux` or `windows`) for POST requests to `/wp-admin/admin-ajax.php` with the `action` parameter set to `install-imprint` using the Sigma rule provided below.
*   Consider implementing a Web Application Firewall (WAF) rule to block requests matching the exploit pattern described in the Attack Chain.
*   Review WordPress user accounts for any unauthorized administrators.
