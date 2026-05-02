---
title: Geo Mashup WordPress Plugin Time-Based SQL Injection
slug: 2026-05-geo-mashup-sqli
description: The Geo Mashup plugin for WordPress is vulnerable to Time-Based SQL Injection via the 'sort' parameter, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-02T12:16:15Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sqli
  - wordpress
  - ge Mashup
  - cve-2026-4060
  - cloud
vendors:
  - WordPress
products:
  - Geo Mashup plugin <= 1.13.18
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4060
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4060
rules:
  - title: Detect Geo Mashup Time-Based SQL Injection Attempt
    description: Detects potential time-based SQL injection attempts in the Geo Mashup plugin 'sort' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Geo Mashup SQL Injection Attempt via OR condition
    description: Detects potential SQL injection attempts in the Geo Mashup plugin 'sort' parameter using OR conditions.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Geo Mashup plugin for WordPress, in versions up to and including 1.13.18, is susceptible to Time-Based SQL Injection. This vulnerability stems from inadequate escaping of the 'sort' parameter, combined with insufficient preparation of the existing SQL query. While the `esc_sql()` function is used, its effectiveness is limited because the 'sort' value is not enclosed in quotes within the `ORDER BY` context. Additionally, a `sanitize_sort_arg()` sanitizer introduced in version 1.13.18 is only applied in the AJAX code path, neglecting `render-map.php` and template tag code paths. This oversight enables unauthenticated attackers to inject malicious SQL queries and extract sensitive data from the WordPress database through a time-based blind SQL injection technique. Successful exploitation allows unauthorized access to potentially sensitive data.

## Attack Chain

1. An unauthenticated attacker identifies a Geo Mashup plugin installation on a WordPress site.
2. The attacker crafts a malicious HTTP request targeting a page that uses the `render-map.php` or template tag code paths.
3. The crafted request includes the 'sort' parameter with a SQL injection payload designed to trigger a time delay based on a condition. For example: `http://example.com/wp-content/plugins/geo-mashup/render-map.php?sort=name) AND IF(substring(user(),1,1)='a',sleep(5),0)/*`.
4. The WordPress application processes the request, passing the unsanitized 'sort' parameter to the SQL query without proper sanitization in the vulnerable code paths.
5. The database executes the injected SQL query. If the injected condition is true (e.g., the first letter of the database user is 'a'), the `sleep(5)` function is executed, causing a noticeable delay.
6. The attacker monitors the response time. A delay indicates a successful injection and allows the attacker to infer information about the database content.
7. The attacker repeats steps 3-6 with different SQL injection payloads to extract further information character by character, performing a time-based blind SQL injection.
8. The attacker exfiltrates sensitive information such as usernames, password hashes, API keys, and other confidential data stored in the WordPress database.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to extract sensitive information from the WordPress database. This can lead to complete compromise of the WordPress site, including unauthorized access to user accounts, modification of content, and potential deployment of malware. The impact is significant for any website using the Geo Mashup plugin, potentially affecting thousands of sites until the vulnerability is patched. A CVSS v3.1 score of 7.5 indicates a high severity.

## Recommendation

*   Deploy the following Sigma rule to detect exploitation attempts against the Geo Mashup plugin based on suspicious 'sort' parameter values in web server logs.
*   Upgrade the Geo Mashup plugin to a version greater than 1.13.18, where the vulnerability is patched, ensuring that the fix covers all code paths, including `render-map.php` and template tags.
*   Monitor web server logs for unusual delays or errors when accessing pages associated with the Geo Mashup plugin (category: webserver).
