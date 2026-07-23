---
title: Critical Code Injection Vulnerability in WordPress Customer Support Ticket System & Helpdesk Plugin (CVE-2026-15011)
slug: 2026-07-wordpress-ticket-system-code-injection
description: A critical code injection vulnerability, CVE-2026-15011, affects the Customer Support Ticket System & Helpdesk plugin for WordPress versions up to and including 6.0.5, allowing unauthenticated attackers to invoke arbitrary parameterless PHP functions via the 'path' parameter, potentially disrupting site functionality or exposing sensitive information without prior authentication.
date: "2026-07-23T10:19:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - wordpress
  - web-application
  - plugin-vulnerability
  - php
vendors:
  - WordPress
products:
  - Customer Support Ticket System & Helpdesk plugin for WordPress <= 6.0.5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The Customer Support Ticket System & Helpdesk plugin for WordPress is vulnerable to Code Injection via the 'path' parameter... This makes it possible for unauthenticated attackers to invoke arbitrary parameterless PHP functions.
    confidence_band: high
cves:
  - id: CVE-2026-15011
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15011
---

A critical code injection vulnerability, identified as CVE-2026-15011, has been discovered in the Customer Support Ticket System & Helpdesk plugin for WordPress, affecting all versions up to and including 6.0.5. This flaw stems from insufficient validation of the 'path' parameter, which is then used in dynamic function invocation. This allows unauthenticated attackers to remotely invoke arbitrary parameterless PHP functions. A key aspect of this vulnerability is that the required security nonce for exploitation is publicly emitted via `wp_localize_script` on any public-facing page that renders the plugin's `[emd_form]` shortcode. This makes the exploitation vector readily accessible to unauthenticated visitors without needing any prior authentication or special privileges. Successful exploitation can lead to significant disruption of website functionality or the exposure of sensitive data stored on the server.

## Attack Chain

1. **Initial Discovery**: An attacker identifies a WordPress instance running the vulnerable Customer Support Ticket System & Helpdesk plugin, specifically version 6.0.5 or earlier.
2. **Nonce Acquisition**: The attacker accesses a public-facing page on the target WordPress site that renders the `[emd_form]` shortcode. From the `wp_localize_script` output on this page, the attacker extracts the necessary security nonce.
3. **Payload Crafting**: The attacker constructs a malicious HTTP GET or POST request targeting an endpoint handled by the vulnerable plugin. This request includes the 'path' parameter, whose value is crafted to be the name of an arbitrary parameterless PHP function (e.g., `phpinfo`, `exit`, `readfile`).
4. **Exploitation Request**: The crafted HTTP request, incorporating the acquired nonce and the malicious 'path' parameter, is sent to the vulnerable WordPress website.
5. **Dynamic Function Invocation**: The vulnerable plugin's code receives the request. Due to the lack of proper input validation, the attacker-controlled value in the 'path' parameter is directly used in a dynamic function invocation.
6. **Impact Execution**: The specified PHP function executes on the server. Depending on the invoked function, this can lead to immediate disruption of the website's operation (e.g., `die()` function) or the exposure of sensitive information (e.g., `phpinfo()` output, reading arbitrary files via `readfile()`).

## Impact

Successful exploitation of CVE-2026-15011 can lead to severe consequences for affected WordPress sites. Attackers can leverage the ability to invoke arbitrary parameterless PHP functions to disrupt the normal operation of the website, potentially rendering it inaccessible or non-functional. Furthermore, this vulnerability can be abused to expose sensitive information residing on the server, including configuration files, user data, or database credentials, which could lead to further compromise or data breaches. While specific victim counts are not available, all organizations utilizing the Customer Support Ticket System & Helpdesk plugin for WordPress in affected versions are at risk.

## Recommendation

* Immediately update the Customer Support Ticket System & Helpdesk plugin for WordPress to a version patched against CVE-2026-15011.
* Review web server access logs for unusual HTTP requests targeting plugin-specific endpoints, especially those containing unexpected or suspicious values in query parameters that might indicate attempts to exploit CVE-2026-15011.
* Implement web application firewall (WAF) rules to detect and block requests that attempt dynamic PHP function invocation via query parameters, particularly targeting the 'path' parameter mentioned in CVE-2026-15011.
