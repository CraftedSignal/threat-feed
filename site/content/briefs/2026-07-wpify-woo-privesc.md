---
title: Wpify Woo Plugin Privilege Escalation Vulnerability (CVE-2026-12736)
slug: 2026-07-wpify-woo-privesc
description: A privilege escalation vulnerability (CVE-2026-12736) in the Wpify Woo plugin for WordPress, affecting versions up to and including 5.4.16, allows authenticated attackers with 'Shop Manager' capabilities or higher to gain Administrator privileges by exploiting a REST route that overwrites arbitrary WordPress options.
date: "2026-07-24T04:18:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - wordpress
  - web-vulnerability
vendors:
  - Wpify
  - WordPress
products:
  - Wpify Woo plugin (<= 5.4.16)
  - WordPress
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers... to elevate their privileges to Administrator by overwriting arbitrary WordPress options (for example setting default_role to administrator and users_can_register to 1, or disabling security plugins via active_plugins).
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for authenticated attackers, with Shop Manager-level access and above, to elevate their privileges to Administrator...
    confidence_band: high
cves:
  - id: CVE-2026-12736
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12736
rules:
  - title: Detect CVE-2026-12736 Exploitation - Wpify Woo Privilege Escalation
    description: Detects exploitation attempts against CVE-2026-12736 in Wpify Woo plugin, where authenticated attackers try to elevate privileges via the vulnerable SettingsApi::save_option() REST route by manipulating WordPress options like default_role or active_plugins.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

A critical privilege escalation vulnerability, tracked as CVE-2026-12736, has been identified in the Wpify Woo plugin for WordPress, impacting all versions up to and including 5.4.16. This flaw stems from improper validation within the `SettingsApi::save_option()` REST route, accessible via `POST /wp-json/wpify-woo/v1/option`. The vulnerable route directly passes user-supplied 'option' and 'data' parameters to WordPress's `update_option()` function without adequate allowlisting or sanitization. This oversight enables authenticated attackers, requiring only 'Shop Manager' level access or higher, to manipulate sensitive WordPress options. Exploitation can lead to the elevation of privileges to Administrator, for instance, by altering the `default_role` to `administrator` and `users_can_register` to `1`, or by disabling critical security plugins through modification of the `active_plugins` option. This vulnerability poses a significant risk as it can grant full control over affected WordPress sites to malicious actors.

## Attack Chain

1. **Initial Access:** An authenticated attacker obtains or compromises credentials for a WordPress user with 'Shop Manager' capabilities or higher on the target site.
2. **Vulnerability Identification:** The attacker identifies the privilege escalation vulnerability in the Wpify Woo plugin, specifically targeting the `SettingsApi::save_option()` REST route at `/wp-json/wpify-woo/v1/option`.
3. **Malicious Request Crafting:** The attacker crafts a HTTP POST request targeting the vulnerable REST endpoint. This request includes the `option` parameter set to a sensitive WordPress option name (e.g., `default_role`, `users_can_register`, or `active_plugins`) and the `data` parameter set to a value that facilitates privilege escalation (e.g., `administrator`, `1`, or a serialized array to disable plugins).
4. **Request Execution:** The attacker sends the specially crafted POST request to the WordPress instance via the vulnerable REST API endpoint.
5. **Option Overwrite:** The vulnerable `SettingsApi::save_option()` function, lacking proper input validation and sanitization, calls `update_option()` with the attacker-controlled `option` and `data` values, overwriting the legitimate WordPress setting.
6. **Privilege Escalation:** The targeted WordPress option is successfully overwritten, leading to an elevated privilege context. For example, `default_role` is set to `administrator` and `users_can_register` to `1`.
7. **Administrator Account Creation/Activation:** The attacker then registers a new user account (if `users_can_register` was enabled and `default_role` set to administrator), or modifies an existing user's role to administrator.
8. **Full Control:** The attacker gains full administrative control over the WordPress site, enabling further malicious activities such as arbitrary code execution, data exfiltration, or website defacement.

## Impact

Successful exploitation of CVE-2026-12736 grants authenticated attackers with 'Shop Manager' level access, or higher, full administrative control over the affected WordPress site. This means attackers can bypass security measures, create new administrator accounts, inject malicious code, deface the website, exfiltrate sensitive data, or install backdoors, leading to complete compromise of the web application and potentially the underlying server. While specific victim counts are not available, all WordPress installations running vulnerable versions of the Wpify Woo plugin are at risk.

## Recommendation

* **Patch CVE-2026-12736** immediately by updating the Wpify Woo plugin to a version beyond 5.4.16 as soon as a fix is available.
* **Deploy the Sigma rule** in this brief to your SIEM to detect exploitation attempts against the `/wp-json/wpify-woo/v1/option` REST route.
* **Review web server access logs** for suspicious POST requests to the `/wp-json/wpify-woo/v1/option` endpoint, especially those containing sensitive WordPress option names like `default_role`, `users_can_register`, or `active_plugins` in the query string.
* **Implement Web Application Firewall (WAF)** rules to block or alert on requests to the `/wp-json/wpify-woo/v1/option` endpoint that attempt to modify core WordPress options, specifically looking for `option=` and `data=` parameters with sensitive values.
