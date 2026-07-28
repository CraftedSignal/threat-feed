---
title: Privilege Escalation in Eazy Plugin Manager for WordPress (CVE-2026-14328)
slug: 2026-07-eazy-plugin-manager-privesc
description: The Eazy Plugin Manager - Powerful Plugin Management Solution for WordPress plugin for WordPress (versions up to and including 4.4.1) is vulnerable to privilege escalation (CVE-2026-14328), allowing authenticated attackers with Subscriber-level access to read sensitive WordPress options, compute an authentication key, and obtain Administrator authentication cookies, leading to full site takeover if the plugin's remote connection feature is configured.
date: "2026-07-28T10:20:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - web
  - privilege-escalation
  - cve-2026-14328
products:
  - Eazy Plugin Manager – Powerful Plugin Management Solution for WordPress <= 4.4.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated attackers, with Subscriber-level access and above, to read the `site_url`, `connection_key`, and `remote_user_id` values stored in the `eazywp_connecting_info` and `eazywp_connection` options, compute the required `auth_key`, call the `admin/login` REST endpoint to obtain Administrator authentication cookies, and fully take over the site.
    confidence_band: high
cves:
  - id: CVE-2026-14328
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14328
rules:
  - title: Detects CVE-2026-14328 Exploitation - Eazy Plugin Manager Option Retrieval
    description: Detects attempts by low-privileged users to retrieve sensitive Eazy Plugin Manager options (eazywp_connecting_info, eazywp_connection) via the vulnerable wp_ajax_pos_get_option AJAX handler, indicative of CVE-2026-14328 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detects CVE-2026-14328 Exploitation - Eazy Plugin Manager Admin Login Endpoint Access
    description: Detects access to the Eazy Plugin Manager's admin_login_endpoint_handler REST endpoint with an 'auth_key' parameter, indicating the final stage of CVE-2026-14328 privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

The Eazy Plugin Manager - Powerful Plugin Management Solution for WordPress plugin, affecting all versions up to and including 4.4.1, contains a critical privilege escalation vulnerability identified as CVE-2026-14328. This flaw stems from insufficient authorization within the `wp_ajax_pos_get_option` AJAX handler, which fails to perform capability checks, relying only on a localized nonce. This handler allows authenticated attackers with Subscriber-level access or higher to retrieve arbitrary WordPress option values. Coupled with the publicly accessible `admin_login_endpoint_handler` REST endpoint (`GET /wp-json/epm/v1/admin/login`), which authenticates users based on a whirlpool hash of values stored in specific options, attackers can extract critical credentials (`site_url`, `connection_key`, `remote_user_id`), calculate the necessary `auth_key`, and bypass authentication to gain Administrator-level access and fully compromise the WordPress site. Exploitation requires the plugin's remote connection feature to be actively configured.

## Attack Chain

1. An authenticated attacker with Subscriber-level access or higher initiates a request to the vulnerable `wp_ajax_pos_get_option` AJAX handler.
2. The attacker leverages the insufficient authorization vulnerability to request the `eazywp_connecting_info` and `eazywp_connection` WordPress options.
3. The plugin's AJAX handler, failing to check user capabilities, returns the values of the requested options, which include sensitive data like `site_url`, `connection_key`, and `remote_user_id`.
4. The attacker uses the retrieved `site_url`, `connection_key`, and `remote_user_id` values to compute the required `auth_key` via a whirlpool hash algorithm as expected by the plugin.
5. The attacker then makes a GET request to the publicly accessible `admin_login_endpoint_handler` REST endpoint at `/wp-json/epm/v1/admin/login`.
6. The computed `auth_key` is supplied to this endpoint, which validates it against the stored whirlpool hash of the sensitive options.
7. Upon successful validation, the attacker is granted Administrator authentication cookies.
8. With Administrator authentication cookies, the attacker achieves full site takeover of the compromised WordPress instance.

## Impact

Successful exploitation of CVE-2026-14328 results in a complete site takeover by an authenticated attacker, allowing them to gain Administrator-level privileges on the affected WordPress site. This grants the attacker full control over the website's content, users, themes, plugins, and settings. Attackers could deface the site, inject malicious code, exfiltrate sensitive data, or use the compromised site for further malicious activities, such as hosting malware or launching phishing campaigns. The prerequisite for exploitation is that the Eazy Plugin Manager's remote connection feature must be enabled and configured on the WordPress site.

## Recommendation

* Immediately update the "Eazy Plugin Manager - Powerful Plugin Management Solution for WordPress" plugin to a patched version beyond 4.4.1 to remediate CVE-2026-14328.
* Deploy the provided Sigma rules to your SIEM to detect attempts at exploiting the `wp_ajax_pos_get_option` AJAX handler and the `admin_login_endpoint_handler` REST endpoint.
* Review web server logs for suspicious requests to `wp-admin/admin-ajax.php` with `action=pos_get_option` and `option_name` parameters, especially for `eazywp_connecting_info` or `eazywp_connection`.
* Monitor web server logs for GET requests to `/wp-json/epm/v1/admin/login` that include an `auth_key` parameter, as this indicates an attempted login using the computed key.
