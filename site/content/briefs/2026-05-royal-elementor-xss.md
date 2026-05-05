---
title: Royal Elementor Addons Plugin Stored XSS Vulnerability
slug: 2026-05-royal-elementor-xss
description: The Royal Elementor Addons plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'status' parameter in the wpr_update_form_action_meta AJAX action, allowing unauthenticated attackers to inject arbitrary web scripts into pages.
date: "2026-05-05T04:16:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - stored-xss
  - cve-2026-4803
  - royal-elementor
vendors:
  - WordPress
products:
  - Royal Elementor Addons plugin <= 1.7.1056
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4803
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4803
rules:
  - title: Detect Royal Elementor Addons XSS Attempt via AJAX
    description: Detects attempts to exploit the Royal Elementor Addons XSS vulnerability by monitoring POST requests to the WordPress AJAX endpoint with potentially malicious JavaScript in the status parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Royal Elementor Addons XSS Attempt via AJAX - No Script Tag
    description: Detects attempts to exploit the Royal Elementor Addons XSS vulnerability by monitoring POST requests to the WordPress AJAX endpoint with potentially malicious JavaScript in the status parameter, even if no <script> tag is present.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Royal Elementor Addons plugin for WordPress, in versions up to and including 1.7.1056, contains a stored Cross-Site Scripting (XSS) vulnerability. This vulnerability stems from a combination of insufficient input sanitization and output escaping of the 'status' parameter within the wpr_update_form_action_meta AJAX action. Critically, the plugin also includes a publicly leaked nonce, granting unauthenticated access to the AJAX handler. An unauthenticated attacker can exploit this flaw to inject malicious JavaScript code into WordPress pages. When a user visits a page containing the injected script, the script executes within the user's browser, potentially leading to session hijacking, defacement, or other malicious actions. This vulnerability poses a significant risk to WordPress sites utilizing the Royal Elementor Addons plugin.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using a vulnerable version (<= 1.7.1056) of the Royal Elementor Addons plugin.
2. The attacker crafts a malicious HTTP POST request targeting the WordPress AJAX endpoint (wp-admin/admin-ajax.php).
3. The POST request includes the action parameter set to 'wpr_update_form_action_meta'.
4. The attacker includes the publicly leaked nonce value to bypass authentication checks for the AJAX action.
5. The attacker injects malicious JavaScript code within the 'status' parameter of the POST request. The code is not properly sanitized by the plugin.
6. The server processes the request and stores the malicious script in the WordPress database.
7. A legitimate user visits a page where the injected content is displayed.
8. The malicious JavaScript code is executed within the user's browser, enabling the attacker to perform actions such as stealing cookies, redirecting the user, or defacing the website.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to inject arbitrary web scripts into WordPress pages. This can lead to a variety of malicious outcomes, including session hijacking, website defacement, and the execution of arbitrary code within the context of a user's browser. Given the widespread use of WordPress and the Royal Elementor Addons plugin, a successful mass exploitation could impact numerous websites and their users, leading to data breaches and reputational damage.

## Recommendation

*   Upgrade the Royal Elementor Addons plugin to the latest version, which includes a fix for CVE-2026-4803.
*   Implement a web application firewall (WAF) rule to filter requests to wp-admin/admin-ajax.php containing suspicious JavaScript code in the 'status' parameter.
*   Deploy the Sigma rule to detect exploitation attempts by monitoring for POST requests to the AJAX endpoint with malicious script content.
*   Review and audit existing WordPress installations for signs of compromise, such as unexpected script injections in pages or database entries.
