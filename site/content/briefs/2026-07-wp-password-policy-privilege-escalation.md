---
title: WP Password Policy Plugin Privilege Escalation via Crafted POST Request (CVE-2026-15992)
slug: 2026-07-wp-password-policy-privilege-escalation
description: The WP Password Policy plugin for WordPress, in versions up to and including 3.7.1, is vulnerable to privilege escalation, allowing authenticated attackers with subscriber-level access to escalate their privileges to Administrator by sending a crafted POST request to the password-reset form endpoint, leveraging missing authorization checks and nonce verification.
date: "2026-07-28T19:21:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - privilege-escalation
  - web-vulnerability
  - php
vendors:
  - WordPress
products:
  - WP Password Policy
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to escalate their own privileges to Administrator by submitting a crafted POST request — with `action` set to `createuser` and `role` set to `administrator` — to the password-reset form endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-15992
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15992
rules:
  - title: Detects CVE-2026-15992 Exploitation - WP Password Policy Privilege Escalation
    description: Detects CVE-2026-15992 exploitation - crafted POST requests to the WordPress login endpoint attempting to escalate privileges via the WP Password Policy plugin.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
rules_count: 1
---

A critical privilege escalation vulnerability, tracked as CVE-2026-15992, affects all versions up to and including 3.7.1 of the WP Password Policy plugin for WordPress. This flaw stems from a lack of authorization checks and nonce verification within the `get_user()` function of the `Module_Password_Hint` class. This allows authenticated attackers, possessing at least subscriber-level access, to exploit the vulnerability by submitting a specially crafted HTTP POST request to the password-reset form endpoint. The plugin's vulnerable code unconditionally calls `WP_User::set_role()` with attacker-controlled `role` parameters, enabling an attacker to elevate their own privileges to that of an Administrator. To exploit this, an attacker must have a valid password-reset cookie, which can be easily obtained by initiating a password reset for their own account. This vulnerability poses a significant risk as it grants full administrative control over the compromised WordPress site.

## Attack Chain

1. An attacker gains or possesses authenticated access to a WordPress site at a subscriber level or higher.
2. The attacker initiates a password reset for their own account on the target WordPress site to obtain a valid password-reset cookie.
3. The attacker crafts a malicious HTTP POST request designed to target the WordPress password-reset form endpoint (typically `wp-login.php`).
4. The crafted POST request includes the `action` parameter set to `createuser` and the `role` parameter set to `administrator`.
5. The vulnerable `get_user()` function within the `Module_Password_Hint` class processes these parameters due to missing authorization checks and nonce verification.
6. The plugin's code unconditionally invokes `WP_User::set_role()` using the attacker-supplied `role` parameter.
7. The attacker's current subscriber-level account is successfully elevated to an Administrator role, granting full control over the WordPress site.

## Impact

Successful exploitation of CVE-2026-15992 allows an authenticated attacker to gain full Administrator privileges on the affected WordPress site. This complete compromise enables the attacker to modify site content, install plugins and themes, delete users, access sensitive data, or inject malicious code, leading to defacement, data theft, or further compromise of the web server. The broad impact extends to any organization or individual using the vulnerable WP Password Policy plugin, regardless of sector.

## Recommendation

* Patch CVE-2026-15992 immediately by updating the WP Password Policy plugin to version 3.7.2 or higher.
* Deploy the Sigma rule "Detects CVE-2026-15992 Exploitation - WP Password Policy Privilege Escalation" to your SIEM to identify attempts at privilege escalation.
* Monitor web server access logs for suspicious POST requests to `/wp-login.php` containing `action=createuser` and `role=administrator` in the query string or request body.
* Regularly review user roles and permissions within your WordPress installations for any unauthorized changes.
