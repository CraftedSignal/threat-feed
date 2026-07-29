---
title: WordPress Wholesale for WooCommerce Plugin Privilege Escalation (CVE-2026-12144)
slug: 2026-07-wordpress-wholesale-privesc
description: The Wholesale for WooCommerce plugin for WordPress is vulnerable to privilege escalation due to insufficient validation and capability checks in `save_requests_meta()` function, allowing authenticated attackers with author-level access or higher to escalate their privileges to administrator by supplying 'administrator' as the `user_role_set` value in a crafted request.
date: "2026-07-29T02:18:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - web-vulnerability
vendors:
  - Rymera Web Co
products:
  - Wholesale for WooCommerce plugin (up to 2.0.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with author-level access and above to escalate their privileges to administrator by supplying `administrator` as the `user_role_set` value in a crafted request.
    confidence_band: high
cves:
  - id: CVE-2026-12144
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12144
---

The Wholesale for WooCommerce plugin for WordPress, in all versions up to and including 2.0.5, contains a critical privilege escalation vulnerability, tracked as CVE-2026-12144. This flaw arises from inadequate validation within the `save_requests_meta()` function, which only applies `sanitize_text_field()` to the `user_role_set` POST parameter before directly passing it to `WP_User::add_role()`. Crucially, the function lacks both an allowlist to restrict permissible roles and a proper capability check, such as `current_user_can('promote_users')`. This oversight enables authenticated attackers with at least author-level privileges to escalate their access to administrator by submitting a crafted request where the `user_role_set` parameter is set to "administrator". The function is protected by a `request_user_role_nonce`, but any author-level user who has published a `wwp_requests` post (e.g., via the wholesale registration form) can easily obtain this nonce from the post edit screen, making exploitation straightforward for an attacker who has gained a low-level authenticated session.

## Attack Chain

1. An authenticated attacker obtains author-level access or higher on a WordPress site running the vulnerable Wholesale for WooCommerce plugin.
2. The attacker identifies or creates a `wwp_requests` custom post type entry, which is typically created via the plugin's wholesale registration form.
3. The attacker accesses the WordPress admin interface to view the edit screen for a `wwp_requests` post.
4. From the post edit screen, the attacker extracts the valid `request_user_role_nonce` value, which is rendered within the meta box.
5. The attacker crafts an HTTP POST request targeting the `save_requests_meta()` function, typically invoked during the saving of the `wwp_requests` post.
6. The crafted request includes the obtained `request_user_role_nonce` for validation and sets the `user_role_set` POST parameter to "administrator".
7. The vulnerable `save_requests_meta()` function processes the request, passes the "administrator" role value to `WP_User::add_role()` without sufficient validation or capability checks.
8. The `WP_User::add_role()` function successfully assigns the administrator role to the attacker's user account, completing the privilege escalation.

## Impact

Successful exploitation of CVE-2026-12144 allows an authenticated attacker, even with low-level privileges such as author, to gain full administrator control over the affected WordPress site. This leads to complete compromise of the website, including the ability to manipulate all content, install malicious plugins, alter themes, modify site settings, steal sensitive data, and potentially pivot to other systems within the hosting environment. The widespread use of WordPress and the WooCommerce ecosystem implies a broad potential victim base for this type of vulnerability, particularly e-commerce sites relying on the Wholesale for WooCommerce plugin.

## Recommendation

* Immediately update the Wholesale for WooCommerce plugin to a version patched against CVE-2026-12144.
* Regularly review WordPress user accounts and their assigned roles for any unauthorized changes.
* Monitor WordPress application logs and security plugin logs for suspicious POST requests to administrative endpoints, especially those involving user role modifications.
* Ensure robust web application firewall (WAF) rules are in place to help detect and block anomalous requests that might indicate exploitation attempts, particularly those targeting `wp-admin/post.php` or similar endpoints with unusual parameters.
