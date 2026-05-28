---
title: Crawlomatic Multipage Scraper Post Generator Plugin RCE (CVE-2026-9009)
slug: 2026-05-crawlomatic-rce
description: The Crawlomatic Multipage Scraper Post Generator plugin for WordPress is vulnerable to remote code execution (RCE) via the 'callback_raw' shortcode attribute, allowing authenticated attackers with author-level access or higher to execute arbitrary code on the server.
date: "2026-05-28T06:17:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-9009
  - rce
  - wordpress
  - plugin
  - crawlomatic
vendors:
  - WordPress
products:
  - Crawlomatic Multipage Scraper Post Generator plugin <= 2.7.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-9009
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9009
  - CVE-2026-9009
rules:
  - title: Detect CVE-2026-9009 Exploitation — Crawlomatic Shortcode RCE Attempt
    description: Detects CVE-2026-9009 exploitation — attempts to use the Crawlomatic plugin shortcode with callback_raw to inject commands
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
  - title: Detect CVE-2026-9009 Exploitation — Crawlomatic Shortcode RCE Attempt via Callback
    description: Detects CVE-2026-9009 exploitation via the 'callback' attribute in the Crawlomatic shortcode, indicating a potential RCE attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
rules_count: 2
---

The Crawlomatic Multipage Scraper Post Generator plugin for WordPress is vulnerable to remote code execution (RCE) in versions up to and including 2.7.2. This vulnerability, identified as CVE-2026-9009, stems from the insecure handling of the 'callback_raw' shortcode attribute within the `filter_content` function. Specifically, the plugin passes the attacker-supplied 'callback_raw' attribute directly into the `call_user_func()` function without adequate sanitization or allowlist validation. The vulnerability is only checked with the `is_callable()` function, which doesn't prevent execution of dangerous PHP built-in functions like `system`, `shell_exec`, `exec`, `passthru`, and `assert`. This allows authenticated attackers with author-level access or higher to execute arbitrary code on the underlying server. A similar vulnerability exists for the 'callback' attribute, providing an alternate attack vector through the same shortcode.

## Attack Chain

1.  Attacker authenticates to the WordPress site with author-level or higher privileges.
2.  Attacker crafts a malicious WordPress post or page containing the `crawlomatic` shortcode.
3.  The shortcode includes the `callback_raw` attribute set to a PHP function that executes arbitrary commands (e.g., `system`).
4.  The crafted post or page is published or previewed.
5.  The `filter_content` function within the Crawlomatic plugin processes the shortcode.
6.  The `callback_raw` attribute value is passed to `call_user_func()` without proper sanitization.
7.  The specified PHP function is executed, resulting in arbitrary code execution on the server.
8.  The attacker gains control of the server, potentially leading to data exfiltration, system compromise, or further malicious activities.

## Impact

Successful exploitation of CVE-2026-9009 allows attackers to execute arbitrary code on the WordPress server. This can lead to complete system compromise, including the ability to read sensitive data, modify files, install malware, and pivot to other systems on the network. Given the widespread use of WordPress, a successful attack could impact numerous websites and organizations relying on the Crawlomatic plugin.

## Recommendation

*   Upgrade the Crawlomatic Multipage Scraper Post Generator plugin to a version higher than 2.7.2 to patch CVE-2026-9009.
*   Deploy the Sigma rule "Detect CVE-2026-9009 Exploitation — Crawlomatic Shortcode RCE Attempt" to detect exploitation attempts in web server logs.
*   Monitor WordPress posts and pages for suspicious use of the `crawlomatic` shortcode with the `callback_raw` attribute containing potentially dangerous PHP functions.
*   Implement strict access control policies to limit author-level privileges and prevent unauthorized users from publishing or modifying content.
