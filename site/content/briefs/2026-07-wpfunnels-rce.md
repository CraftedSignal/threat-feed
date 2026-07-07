---
title: 'CVE-2026-14345: Unauthenticated Remote Code Execution in WPFunnels WordPress Plugin'
slug: 2026-07-wpfunnels-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-14345) exists in the WPFunnels – Funnel Builder for WooCommerce with Checkout & One Click Upsell plugin for WordPress, affecting versions up to and including 3.12.7, allowing attackers to inject malicious PHP code into a log file via the 'postData' parameter, which is then executed when an administrator views the log.
date: "2026-07-07T06:22:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-exploit
  - rce
  - wordpress
  - plugin-vulnerability
vendors:
  - WPFunnels
  - WordPress
products:
  - WPFunnels – Funnel Builder for WooCommerce with Checkout & One Click Upsell plugin <= 3.12.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WPFunnels plugin for WordPress is vulnerable to Remote Code Execution ... This makes it possible for unauthenticated attackers to execute code on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: unsanitized write of attacker-controlled postData values into a PHP-includeable .log file combined with the use of include_once to render that file... attacker-controlled postData values ... malicious PHP code ... resulting in RCE.
    confidence_band: high
cves:
  - id: CVE-2026-14345
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14345
---

A critical unauthenticated Remote Code Execution (RCE) vulnerability, tracked as CVE-2026-14345, has been identified in the WPFunnels – Funnel Builder for WooCommerce with Checkout & One Click Upsell plugin for WordPress, impacting all versions up to and including 3.12.7. This flaw allows unauthenticated attackers to execute arbitrary code on the server by exploiting an unsanitized write of attacker-controlled data from the 'postData' parameter into a PHP-includeable `.log` file. The vulnerability is triggered when an administrator subsequently views the polluted log file via the plugin's Log Settings View UI, leading to the execution of the injected code via `include_once`. While this requires the "Enable Logs" setting to be active and an administrator viewing the log, the nonce needed for the initial injection step is publicly exposed on every funnel step page, making the initial code injection fully unauthenticated.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site utilizing a vulnerable version (<= 3.12.7) of the WPFunnels plugin, where the "Enable Logs" setting is active.
2.  The attacker accesses any publicly available funnel step page on the target WordPress site to harvest the nonce, which is publicly emitted and required for the next step.
3.  The attacker crafts a malicious HTTP POST request targeting the plugin's "optin endpoint," embedding PHP code within the 'postData' parameter, along with the previously retrieved nonce.
4.  Due to improper input sanitization, the vulnerable WPFunnels plugin writes the attacker-controlled 'postData', including the malicious PHP code, directly into a PHP-includeable `.log` file on the web server's filesystem.
5.  An administrator of the WordPress site later navigates to the WPFunnels plugin's Log Settings View UI within the WordPress administrative dashboard, potentially for routine monitoring or troubleshooting.
6.  Upon viewing the logs, the plugin's `wpfnl_show_log` function uses `include_once` to render the content of the polluted `.log` file.
7.  The `include_once` call executes the malicious PHP code previously injected by the attacker, leading to unauthenticated Remote Code Execution on the underlying web server.

## Impact

Successful exploitation of CVE-2026-14345 results in unauthenticated Remote Code Execution (RCE) on the vulnerable WordPress web server. This provides attackers with full control over the compromised server, enabling them to deface the website, inject malware, exfiltrate sensitive data, establish persistence, or use the server as a pivot point for further attacks on the internal network. The CVSS v3.1 base score of 9.8 indicates a critical severity, highlighting the ease of exploitation and significant potential for damage, impacting any organization running the affected plugin versions.

## Recommendation

*   Patch CVE-2026-14345 immediately by updating the "WPFunnels – Funnel Builder for WooCommerce with Checkout & One Click Upsell plugin" to a version greater than 3.12.7.
*   Review WordPress `webserver` access logs for unusual POST requests targeting plugin-related "optin endpoints" that might contain suspicious data in the request body, indicating exploitation attempts for CVE-2026-14345.
*   Monitor file integrity and changes within the `wp-content/plugins/wpfunnels/` directory, specifically looking for unexpected modifications or creations of `.log` or `.php` files.
*   If the plugin's "Enable Logs" setting is not essential for operational requirements, consider disabling it to eliminate the log file pollution vector associated with CVE-2026-14345.
