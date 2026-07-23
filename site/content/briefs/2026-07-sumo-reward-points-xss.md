---
title: SUMO Reward Points WordPress Plugin Vulnerable to Unauthenticated Stored XSS via REST API (CVE-2026-7534)
slug: 2026-07-sumo-reward-points-xss
description: The SUMO Reward Points plugin for WordPress, versions up to and including 32.7.0, is vulnerable to CVE-2026-7534, an Unauthenticated Stored Cross-Site Scripting flaw that allows attackers to inject arbitrary web scripts into the reward points log via the `/wp-json/wc-srp/v1/earning` REST API endpoint, executing when an administrator accesses specific admin pages.
date: "2026-07-23T06:18:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - xss
  - web-vulnerability
  - plugin
  - stored-xss
vendors:
  - SUMO
  - WordPress
products:
  - SUMO Reward Points plugin < 32.7.0
  - WordPress
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts into the reward points log that will execute whenever an administrator accesses the Master Log or User Reward Points admin pages.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The SUMO Reward Points plugin for WordPress is vulnerable to Unauthenticated Stored Cross-Site Scripting via the REST API endpoint `/wp-json/wc-srp/v1/earning`
    confidence_band: high
cves:
  - id: CVE-2026-7534
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7534
rules:
  - title: Detects CVE-2026-7534 Exploitation - SUMO Reward Points Plugin Stored XSS
    description: Detects CVE-2026-7534 exploitation - HTTP POST to /wp-json/wc-srp/v1/earning with script-like content in the 'reason' parameter, indicating an attempt at Stored Cross-Site Scripting in the SUMO Reward Points plugin.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, identified as CVE-2026-7534, has been discovered in the SUMO Reward Points plugin for WordPress, affecting all versions up to and including 32.7.0. This flaw allows unauthenticated attackers to perform Stored Cross-Site Scripting (XSS) by injecting arbitrary web scripts into the reward points log. The vulnerability stems from an improper capability grant (`rs_earning_read`) to all users, including unauthenticated visitors, combined with a lack of sanitization for the `reason` parameter in the `create_items()` function and missing output escaping in the `column_default()` method of `SRP_Master_Log`. Attackers can exploit this by sending a crafted request to the `/wp-json/wc-srp/v1/earning` REST API endpoint. The injected scripts subsequently execute whenever an administrator views the Master Log or User Reward Points admin pages, leading to potential administrative compromise, session hijacking, or further payload delivery.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP POST request containing JavaScript payload within the `reason` parameter.
2. The attacker sends this request to the vulnerable REST API endpoint `/wp-json/wc-srp/v1/earning`.
3. Due to the `user_has_cap` filter unconditionally granting `rs_earning_read` capability to all users, the request is processed even without authentication.
4. The `create_items()` function processes the request without properly sanitizing the `reason` parameter, storing the malicious script in the reward points log.
5. An administrator later accesses the WordPress admin dashboard and navigates to the Master Log or User Reward Points admin pages.
6. The `column_default()` method of `SRP_Master_Log` retrieves the stored log entry without proper output escaping.
7. The malicious JavaScript injected by the attacker executes within the administrator's browser context.
8. The attacker gains control over the administrator's session, performs actions on their behalf, or redirects them to a malicious site.

## Impact

Successful exploitation of CVE-2026-7534 leads to unauthenticated Stored Cross-Site Scripting, allowing attackers to execute arbitrary malicious scripts within the browser of any administrator viewing the affected log pages. This can result in session hijacking, complete administrative control over the WordPress site, redirection to phishing sites, or further client-side attacks. The wide adoption of WordPress and this plugin means that a significant number of websites are potentially at risk, and exploitation could lead to substantial data breaches, website defacement, or malware distribution to site visitors. The CVSS v3.1 Base Score of 7.2 indicates a high severity risk.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to detect attempts at exploiting CVE-2026-7534 against the `/wp-json/wc-srp/v1/earning` endpoint.
* Monitor web server access logs for HTTP POST requests containing script-like content in the query parameters targeting `/wp-json/wc-srp/v1/earning`.
* Patch CVE-2026-7534 by updating the SUMO Reward Points plugin for WordPress to a version greater than 32.7.0 immediately.
* Implement a Web Application Firewall (WAF) with rules to detect and block XSS payloads in request parameters, specifically for the `/wp-json/wc-srp/v1/earning` REST API endpoint.
