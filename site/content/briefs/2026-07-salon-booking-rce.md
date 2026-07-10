---
title: 'CVE-2026-15070: WordPress Salon Booking Plugin CSRF to RCE'
slug: 2026-07-salon-booking-rce
description: The Salon Booking System - Free Version plugin for WordPress (versions up to and including 10.30.32) is susceptible to a Cross-Site Request Forgery (CSRF) vulnerability stemming from a lack of nonce validation in the setCustomText function, allowing unauthenticated attackers to inject arbitrary PHP code into the web-accessible translate-constants.php file, which can lead to remote code execution (RCE) on the server if an administrator is tricked into clicking a crafted link.
date: "2026-07-10T04:21:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-exploitation
  - vulnerability
  - wordpress
  - rce
  - csrf
vendors:
  - WordPress
products:
  - Salon Booking System - Free Version plugin for WordPress <= 10.30.32
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: granted they can trick a site administrator into performing an action such as clicking on a link.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Salon Booking System – Free Version plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 10.30.32. This is due to missing or incorrect nonce validation on the setCustomText function.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary PHP code into the web-accessible translate-constants.php file within the plugin directory, enabling remote code execution on the server
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15070
rules:
  - title: Detects CVE-2026-15070 Exploitation Attempt - WordPress Salon Booking Plugin CSRF to RCE
    description: Detects CVE-2026-15070 exploitation attempts against the WordPress Salon Booking System - Free Version plugin, specifically looking for POST requests to admin-ajax.php with action=setCustomText and PHP code injection indicators in the query string or request body.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The Salon Booking System - Free Version plugin for WordPress, in all versions up to and including 10.30.32, is vulnerable to Cross-Site Request Forgery (CSRF) via CVE-2026-15070. This flaw originates from missing or incorrect nonce validation within the `setCustomText` function. This allows unauthenticated attackers to inject arbitrary PHP code into the `translate-constants.php` file, which is directly accessible over the web. The vulnerability is exploitable because the `sanitize_text_field()` function, applied to the POST 'value' parameter, fails to neutralize critical characters like single quotes, parentheses, semicolons, dollar signs, and brackets. If an administrator is successfully tricked into clicking a crafted link, the attacker can achieve remote code execution on the server, posing a significant threat to the integrity and availability of the WordPress site.

## Attack Chain

1. An unauthenticated attacker crafts a malicious Cross-Site Request Forgery (CSRF) payload designed to target the vulnerable `setCustomText` function of the Salon Booking System plugin.
2. The attacker socially engineers an authenticated administrator of the target WordPress site to click on a crafted link (e.g., via phishing email or malicious website).
3. The administrator's browser, authenticated to the WordPress site, sends the forged POST request containing the malicious PHP code as part of the 'value' parameter.
4. Due to the absence of proper nonce validation, the WordPress site processes the request as legitimate, invoking the vulnerable `setCustomText` function.
5. The `setCustomText` function, which uses `sanitize_text_field()` on the 'value' parameter, fails to adequately neutralize PHP metacharacters within the attacker-supplied input.
6. The unneutralized arbitrary PHP code is then interpolated into a string literal and written to the `translate-constants.php` file within the plugin's directory via `file_put_contents()`.
7. The attacker then directly accesses the now-modified and web-accessible `translate-constants.php` file, causing the injected PHP code to execute on the server.
8. Remote Code Execution (RCE) is achieved, granting the attacker control over the compromised WordPress server.

## Impact

Successful exploitation of CVE-2026-15070 allows unauthenticated attackers to achieve remote code execution on the compromised WordPress server. This can lead to complete compromise of the website and underlying server, including data theft, defacement, installation of malware, establishment of persistent backdoors, and further network infiltration. The severity of the impact is high, as an attacker gaining RCE can fully control the affected system, affecting all data and services hosted on it. There are no specific victim counts or sectors mentioned, but any organization using the vulnerable plugin is at risk.

## Recommendation

* Immediately update the Salon Booking System - Free Version plugin for WordPress to a version patched against CVE-2026-15070 (version 10.30.33 or later).
* Deploy the provided Sigma rule to your webserver logs to detect attempts to exploit CVE-2026-15070.
* Configure web application firewalls (WAFs) to block requests to `/wp-admin/admin-ajax.php` that contain common PHP code injection patterns in POST parameters.
