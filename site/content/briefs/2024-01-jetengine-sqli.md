---
title: JetEngine WordPress Plugin SQL Injection Vulnerability (CVE-2026-4352)
slug: 2024-01-jetengine-sqli
description: The JetEngine plugin for WordPress is vulnerable to SQL Injection via the Custom Content Type (CCT) REST API search endpoint, allowing unauthenticated attackers to extract sensitive database information.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - wordpress
  - jetengine
  - cve-2026-4352
  - web-application
vendors:
  - JetEngine
products:
  - JetEngine plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4352
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4352
rules:
  - title: JetEngine CCT SQLi Detection
    description: Detects potential SQL injection attempts in the JetEngine plugin via the CCT REST API endpoint based on suspicious characters in cs-uri-query.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: JetEngine CCT SQLi via version() Function
    description: Detects potential SQL injection attempts in the JetEngine plugin CCT API endpoint by detecting the use of version() function.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The JetEngine plugin for WordPress, a popular tool for creating custom content types, is vulnerable to SQL Injection via the Custom Content Type (CCT) REST API search endpoint. This vulnerability affects all versions up to and including 3.8.6.1. The root cause is the unsafe interpolation of the `_cct_search` parameter into a SQL query using `sprintf()` without proper sanitization or the use of `$wpdb->prepare()`.  The WordPress REST API's `wp_unslash()` function, which strips `wp_magic_quotes()` protection from the `$_GET` array, exacerbates the issue. Exploitation requires the Custom Content Types module to be enabled, with at least one CCT configured with a public REST GET endpoint. This vulnerability enables unauthenticated attackers to inject malicious SQL queries and potentially extract sensitive information from the WordPress database.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using JetEngine plugin version 3.8.6.1 or earlier with at least one Custom Content Type configured with a public REST GET endpoint.
2. The attacker crafts a malicious HTTP GET request to the CCT REST API endpoint, including a SQL injection payload within the `_cct_search` parameter.
3. The WordPress REST API receives the request and calls the `wp_unslash()` function to strip the `wp_magic_quotes()` protection from the `$_GET` array, allowing the SQL injection payload to pass unfiltered.
4. The JetEngine plugin uses `sprintf()` to directly interpolate the unsanitized `_cct_search` parameter into a SQL query string.
5. The injected SQL code is executed against the WordPress database.
6. The attacker leverages the SQL injection to extract sensitive information such as user credentials, API keys, or other confidential data stored in the database.
7. The attacker may further exploit the vulnerability to modify or delete data within the database, potentially leading to a complete compromise of the WordPress site.
8. The attacker uses the compromised site as a beachhead for further attacks against the wider network infrastructure.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-4352) can lead to the complete compromise of a WordPress website. An attacker can gain access to sensitive data, including user credentials, configuration files, and other confidential information stored within the database. This can result in data breaches, financial loss, and reputational damage. Given the widespread use of WordPress and the JetEngine plugin, a large number of websites are potentially vulnerable.

## Recommendation

*   Upgrade the JetEngine plugin to the latest version (greater than 3.8.6.1) to patch CVE-2026-4352.
*   Deploy the Sigma rule `JetEngine_CCT_SQLi_Detection` to detect attempts to exploit this vulnerability via suspicious characters in the cs-uri-query field within web server logs.
*   Disable public REST GET endpoints for CCTs unless absolutely necessary to reduce the attack surface.
*   Review and sanitize all user-supplied input before using it in database queries to prevent SQL injection vulnerabilities.
