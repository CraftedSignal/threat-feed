---
title: WP Job Portal Plugin SQL Injection Vulnerability
slug: 2026-03-wp-job-portal-sqli
description: The WP Job Portal plugin for WordPress is vulnerable to SQL Injection via the 'radius' parameter, allowing unauthenticated attackers to extract sensitive database information in versions up to 2.4.8.
date: "2026-03-24T12:00:00Z"
type: coverage
types:
  - coverage
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

The WP Job Portal plugin for WordPress, a widely used plugin for managing job listings, is susceptible to SQL Injection attacks. This vulnerability, identified as CVE-2026-4306, affects all versions up to and including 2.4.8. The flaw stems from the insufficient sanitization of the 'radius' parameter, which is directly incorporated into SQL queries without proper escaping. This lack of input validation enables unauthenticated attackers to inject malicious SQL code into the application's database queries. Successful exploitation could lead to the unauthorized disclosure of sensitive information stored within the WordPress database. Given the popularity of WordPress and the WP Job Portal plugin, a successful attack could impact a large number of websites and expose confidential data, including user credentials, financial details, and other sensitive information.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP request targeting the WordPress website running the vulnerable WP Job Portal plugin.
2.  The attacker appends a SQL injection payload to the 'radius' parameter within the HTTP request.
3.  The vulnerable plugin receives the request and incorporates the unsanitized 'radius' parameter into an SQL query within `includes/ajax.php` or `modules/job/model.php`.
4.  The injected SQL code is executed against the WordPress database due to the lack of proper input validation and escaping.
5.  The attacker leverages the SQL injection to extract sensitive information from the database, such as user credentials, API keys, or other confidential data.
6.  The extracted data may be exfiltrated from the server using various techniques.
7.  The attacker could potentially use the compromised data to gain further access to the WordPress site or connected systems.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-4306) could lead to the complete compromise of the WordPress database. Attackers could gain access to sensitive information, including user credentials, customer data, and confidential business information. The vulnerability impacts all users running WP Job Portal plugin versions 2.4.8 and earlier. The CVSS v3.1 score is 7.5, indicating a high severity risk. The impact includes unauthorized data access.

## Recommendation

*   Upgrade the WP Job Portal plugin to version 2.4.9 or later to patch the SQL Injection vulnerability (CVE-2026-4306).
*   Deploy a web application firewall (WAF) with rules to detect and block SQL Injection attempts targeting the 'radius' parameter in WordPress plugins.
*   Enable detailed logging for your web server (category "webserver", product "linux|windows") to monitor for suspicious activity and potential exploitation attempts.
