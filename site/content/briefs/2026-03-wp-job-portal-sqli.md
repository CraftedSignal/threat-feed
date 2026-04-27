---
title: WP Job Portal Plugin SQL Injection Vulnerability
slug: 2026-03-wp-job-portal-sqli
description: The WP Job Portal plugin for WordPress is vulnerable to SQL Injection via the 'radius' parameter, allowing unauthenticated attackers to extract sensitive database information in versions up to 2.4.8.
date: "2026-03-24T12:00:00Z"
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4306
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/ecc34552-c9b0-455f-b1c7-b31cc847cb22?source=cve
rules:
  - title: Detect SQL Injection attempts in WP Job Portal Plugin via Radius Parameter
    description: Detects potential SQL injection attempts targeting the 'radius' parameter in the WP Job Portal plugin for WordPress. This rule looks for common SQL injection syntax within the URI query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting access to sensitive files after potential SQLi in WP Job Portal
    description: This rule detects access attempts to sensitive WordPress files after a successful SQL Injection in the WP Job Portal plugin. This helps in identifying post-exploitation activity
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The WP Job Portal plugin for WordPress, a widely used plugin for managing job listings, is susceptible to SQL Injection attacks. This vulnerability, identified as CVE-2026-4306, affects all versions up to and including 2.4.8. The flaw stems from the insufficient sanitization of the 'radius' parameter, which is directly incorporated into SQL queries without proper escaping. This lack of input validation enables unauthenticated attackers to inject malicious SQL code into the application's…
