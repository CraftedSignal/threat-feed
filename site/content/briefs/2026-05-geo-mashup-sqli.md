---
title: Geo Mashup WordPress Plugin Vulnerable to Time-Based SQL Injection (CVE-2026-4062)
slug: 2026-05-geo-mashup-sqli
description: The Geo Mashup WordPress plugin is vulnerable to Time-Based SQL Injection due to insufficient input sanitization, allowing unauthenticated attackers to extract sensitive database information.
date: "2026-05-02T12:16:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - wordpress
  - plugin
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
  - id: CVE-2026-4062
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4062
rules:
  - title: Detect Geo Mashup Time-Based SQL Injection Attempts
    description: Detects potential time-based SQL injection attempts in the Geo Mashup plugin via the 'object_ids' or 'exclude_object_ids' parameters by looking for SQL `SLEEP()` or `BENCHMARK()` functions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Geo Mashup SQL Error Messages
    description: Detects potential SQL injection attempts by monitoring for SQL error messages in the web server logs related to Geo Mashup plugin requests.
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

The Geo Mashup plugin for WordPress, in versions up to and including 1.13.18, contains a Time-Based SQL Injection vulnerability (CVE-2026-4062). The vulnerability exists within the 'object_ids' and 'exclude_object_ids' parameters. Insufficient escaping of user-supplied input, specifically within the `IN(...)` and `NOT IN(...)` SQL context, coupled with inadequate preparation of the existing SQL query, allows for the injection. The `esc_sql()` function is applied but is rendered ineffective due to its inability to protect against parenthesis or SQL keyword injection within the unquoted `IN(...)` / `NOT IN(...)` context. A numeric-only sanitizer exists in `sanitize_query_args()`, but this is only applied in the AJAX code path and not in the `render-map.php` or template tag code paths. This flaw enables unauthenticated attackers to append malicious SQL queries, facilitating the extraction of sensitive information from the WordPress database through a time-based blind SQL injection technique.

## Attack Chain

1.  An unauthenticated attacker identifies the vulnerable Geo Mashup plugin running on a WordPress site.
2.  The attacker crafts a malicious HTTP request targeting an endpoint that utilizes the 'object_ids' or 'exclude_object_ids' parameters.
3.  The attacker injects a time-based SQL injection payload into the 'object_ids' or 'exclude_object_ids' parameter. This payload leverages SQL functions like `SLEEP()` or `BENCHMARK()` to introduce delays based on conditional SQL logic.
4.  The vulnerable code fails to properly sanitize the injected SQL code due to the ineffective `esc_sql()` function in the `IN`/`NOT IN` context.
5.  The injected SQL payload is appended to the existing SQL query executed by the Geo Mashup plugin.
6.  The database server executes the combined query, including the injected time-based SQL injection.
7.  The attacker monitors the response time of the HTTP request. A delayed response indicates that the injected SQL logic evaluated to true.
8.  By repeatedly sending requests with different SQL injection payloads, the attacker can extract sensitive information from the database one character at a time.

## Impact

Successful exploitation of this vulnerability can lead to the complete compromise of the WordPress database. An attacker can extract sensitive information such as user credentials, API keys, configuration details, and other confidential data. This can result in data breaches, unauthorized access to the WordPress site, and potential further attacks on connected systems. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high severity.

## Recommendation

*   Upgrade the Geo Mashup plugin to a version greater than 1.13.18 to remediate CVE-2026-4062.
*   Deploy the Sigma rule `Detect Geo Mashup Time-Based SQL Injection Attempts` to identify potential exploitation attempts targeting the vulnerable parameters.
*   Monitor web server logs for suspicious requests containing SQL injection payloads in the 'object_ids' or 'exclude_object_ids' parameters to detect exploitation attempts.
