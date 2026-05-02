---
title: Geo Mashup WordPress Plugin Vulnerable to Time-Based SQL Injection (CVE-2026-4061)
slug: 2026-05-geo-mashup-sql-injection
description: A time-based SQL injection vulnerability (CVE-2026-4061) exists in the Geo Mashup WordPress plugin (<= 1.13.18) due to insufficient sanitization of the 'map_post_type' parameter, enabling unauthenticated attackers to extract sensitive information via time-based blind SQL injection if the Geo Search feature is enabled.
date: "2026-05-02T12:16:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - plugin
vendors:
  - WordPress
products:
  - Geo Mashup plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4061
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4061
rules:
  - title: Detect Geo Mashup SQL Injection Attempt via map_post_type
    description: Detects potential time-based SQL injection attempts in the Geo Mashup plugin by identifying POST requests to admin-ajax.php with suspicious map_post_type parameters containing SQL injection keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Geo Mashup SQL Injection Attempt via map_post_type - Error Based
    description: Detects potential error based SQL injection attempts in the Geo Mashup plugin by identifying POST requests to admin-ajax.php with suspicious map_post_type parameters containing SQL injection keywords.
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

The Geo Mashup plugin for WordPress is vulnerable to time-based SQL injection, as detailed in CVE-2026-4061. This vulnerability affects all versions of the plugin up to and including 1.13.18. The root cause lies in the `SearchResults` hook, where the `map_post_type` parameter is mishandled. Specifically, the code first calls `stripslashes_deep($_POST)`, effectively removing WordPress's magic quotes protection. Subsequently, the unsanitized `map_post_type` value is directly concatenated into an `IN(...)` clause without proper escaping using `esc_sql()` or `$wpdb->prepare()`. While the 'any' branch of the code correctly applies `array_map('esc_sql', ...)`, the alternative branch lacks this crucial sanitization step. Successful exploitation requires the Geo Search feature to be enabled in the plugin's settings. This vulnerability allows unauthenticated attackers to inject malicious SQL queries, potentially leading to the extraction of sensitive database information through time-based blind techniques.

## Attack Chain

1.  The attacker identifies a WordPress site using a vulnerable version of the Geo Mashup plugin (<= 1.13.18) with the Geo Search feature enabled.
2.  The attacker crafts a malicious HTTP POST request targeting the `SearchResults` hook with a specially crafted `map_post_type` parameter containing SQL injection payload.
3.  The vulnerable code within the Geo Mashup plugin processes the POST request, removing magic quotes using `stripslashes_deep($_POST)`.
4.  The unsanitized `map_post_type` value is then concatenated directly into an SQL query within an `IN(...)` clause without proper escaping.
5.  The injected SQL code executes within the database query, allowing the attacker to manipulate the query's behavior.
6.  The attacker uses time-based SQL injection techniques (e.g., `IF(condition, SLEEP(5), 0)`) within the injected payload to infer information based on the response time.
7.  By repeatedly sending modified requests and observing the response times, the attacker can extract sensitive data, character by character, from the database.
8.  The attacker extracts sensitive information such as usernames, passwords, API keys, or other confidential data stored in the WordPress database.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to extract sensitive information from the WordPress database. The severity of the impact depends on the sensitivity of the data stored in the database, but could include exposure of user credentials, confidential business data, or other sensitive information. Because it affects any installation with the Geo Search feature enabled, a large number of websites using the Geo Mashup plugin may be vulnerable. The CVSS v3.1 base score is 7.5, indicating a high severity vulnerability.

## Recommendation

*   Upgrade the Geo Mashup plugin to the latest version (later than 1.13.18) to patch CVE-2026-4061.
*   Deploy the provided Sigma rule to detect potential exploitation attempts targeting the vulnerable `SearchResults` hook using a malicious `map_post_type` parameter.
*   Review web server logs for suspicious POST requests to `/wp-admin/admin-ajax.php` (common AJAX endpoint in WordPress) containing potentially malicious SQL injection payloads in the `map_post_type` parameter.
