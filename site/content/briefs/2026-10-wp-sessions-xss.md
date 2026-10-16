---
title: Stored Cross-Site Scripting in WP Sessions Time Monitoring Plugin
slug: 2026-10-wp-sessions-xss
description: The WP Sessions Time Monitoring Full Automatic WordPress plugin up to version 1.1.5 is vulnerable to stored XSS via multiple input parameters, allowing unauthenticated attackers to execute arbitrary scripts in the context of user sessions.
date: "2026-10-16T12:26:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_sessions_time_monitoring_full_automatic_project:wp_sessions_time_monitoring_full_automatic:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - wordpress
  - xss
vendors:
  - WordPress
products:
  - WP Sessions Time Monitoring Full Automatic (<= 1.1.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-107648
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107648
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade the WP Sessions Time Monitoring Full Automatic plugin to the latest patched version.
      owner: IT Operations
      due: 24h
      evidence: Source document identifies the plugin version 1.1.5 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Update WP Sessions Time Monitoring Full Automatic to a version beyond 1.1.5.
      owner: IT Operations
      addresses: CVE-2026-107648
      evidence: Plugin version 1.1.5 and earlier are vulnerable.
---

The WP Sessions Time Monitoring Full Automatic plugin for WordPress (all versions up to and including 1.1.5) contains a critical security flaw involving insufficient input sanitization and output escaping. This vulnerability allows an unauthenticated attacker to perform Stored Cross-Site Scripting (XSS) attacks by injecting malicious JavaScript via various input parameters, including 'action', 'function', 'plugin', 'post_type', 'post_status', 'ids', 'loggedout', and 'post_title'. 

When an administrative user or a logged-in user views a page where the attacker has successfully stored this malicious script, the code executes within the victim's browser session. This can lead to unauthorized account actions, session hijacking, or the defacement of the affected WordPress site. Because the vulnerability is exploitable by unauthenticated attackers, it represents a significant risk to site integrity and administrative session security.

## Attack Chain

1. An unauthenticated attacker identifies a target WordPress site running the WP Sessions Time Monitoring Full Automatic plugin version 1.1.5 or earlier.
2. The attacker crafts a malicious HTTP POST or GET request targeting the vulnerable endpoints within the plugin.
3. The attacker injects a persistent JavaScript payload into one of the susceptible parameters: 'action', 'function', 'plugin', 'post_type', 'post_status', 'ids', 'loggedout', or 'post_title'.
4. The plugin fails to sanitize the input and stores the script directly into the WordPress database.
5. The attacker waits for an authenticated administrator or user to navigate to the specific page or dashboard area that renders the malicious entry.
6. The victim's browser retrieves the stored payload from the database and executes the JavaScript in the context of the active session.
7. The script performs unauthorized actions on behalf of the victim or exfiltrates session cookies to an attacker-controlled server.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of site administrators. This can lead to full administrative account takeover, modification of site content, installation of additional backdoors via the WordPress admin panel, or theft of sensitive user data. As of the report date, all installations using version 1.1.5 or earlier are considered vulnerable.

## Recommendation

* Immediately update the "WP Sessions Time Monitoring Full Automatic" plugin to the latest version, ensuring the patch is applied for CVE-2026-107648.
* Monitor web server access logs for anomalous POST requests containing script-related characters such as `<script`, `onerror=`, or `onload=` within the identified vulnerable parameters.
* Implement a Content Security Policy (CSP) to restrict the execution of inline scripts and mitigate the impact of stored XSS vulnerabilities.
