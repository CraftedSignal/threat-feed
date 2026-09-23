---
title: SQL Injection in Rename wp-login.php WordPress Plugin
slug: 2026-09-wordpress-sqli
description: The 'Rename wp-login.php to anything you want' WordPress plugin is vulnerable to unauthenticated time-based SQL injection via the 'log' parameter, allowing sensitive database information extraction.
date: "2026-09-23T10:42:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rename_wp-login.php_to_anything_you_want_project:rename_wp-login.php_to_anything_you_want:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Rename wp-login.php to anything you want (<= 2.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Rename wp-login.php to anything you want plugin for WordPress is vulnerable to time-based SQL Injection via 'log' (Username) Parameter
    confidence_band: high
cves:
  - id: CVE-2026-93368
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93368
rules:
  - title: Detects CVE-2026-93368 Exploitation - SQL Injection in WordPress Plugin
    description: Detects potential time-based SQL injection attempts against the vulnerable 'Rename wp-login.php to anything you want' plugin by monitoring for SQL keywords in the 'log' POST parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit WordPress site plugins for 'Rename wp-login.php to anything you want' and verify current version
      owner: IT Operations
      due: 24h
      evidence: Source report on CVE-2026-93368
  mitigation_plan:
    - priority: immediate
      action: Deactivate or update the affected WordPress plugin to a version beyond 2.0.1
      owner: IT Operations
      addresses: CVE-2026-93368
      evidence: Plugin version 2.0.1 identified as the last vulnerable version
---

The 'Rename wp-login.php to anything you want' plugin for WordPress (all versions up to and including 2.0.1) contains a critical security vulnerability identified as CVE-2026-93368. The vulnerability is a time-based SQL injection occurring within the 'log' (username) parameter. The flaw stems from insufficient input sanitization and the application of WordPress core 'wp_unslash()' function on user-supplied data before it reaches the plugin's handler. By stripping backslash escaping, this function allows raw single quotes to reach the database query unimpeded. Unauthenticated attackers can leverage this to append malicious SQL queries to existing ones, potentially leading to unauthorized data exfiltration from the WordPress database. Given that the 'log' parameter is processed during login attempts, this provides an accessible vector for attackers to perform blind SQL injection attacks by measuring database response times.

## Impact

Successful exploitation allows unauthenticated attackers to perform SQL injection against the underlying database. This could result in unauthorized access to sensitive information stored in the WordPress database, including user credentials, configuration data, and site content. Since the vulnerability does not require administrative privileges, any internet-facing WordPress site running this plugin version is at risk of information disclosure.

## Recommendation

Immediate action is required for all WordPress installations utilizing the 'Rename wp-login.php to anything you want' plugin.

* Update the plugin to the latest version (patch for CVE-2026-93368) as soon as it is released by the developer.
* If an update is unavailable, deactivate and uninstall the plugin to eliminate the vulnerable code path.
* Implement Web Application Firewall (WAF) rules to inspect the 'log' parameter for common SQL injection characters (such as single quotes and sleep/benchmark functions) specifically targeting requests to the plugin's custom login endpoint.
* Monitor web server logs for suspicious POST requests to the login page containing SQL injection patterns.
