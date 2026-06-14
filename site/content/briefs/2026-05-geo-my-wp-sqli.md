---
title: GEO my WP WordPress Plugin SQL Injection Vulnerability (CVE-2026-9757)
slug: 2026-05-geo-my-wp-sqli
description: The GEO my WP plugin for WordPress is vulnerable to SQL Injection (CVE-2026-9757) via the 'swlatlng' and 'nelatlng' parameters, allowing unauthenticated attackers to extract sensitive information from the database by injecting SQL queries into a BETWEEN clause.
date: "2026-05-30T10:17:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - sqli
  - wordpress
  - plugin
  - geomywp
vendors:
  - WordPress
products:
  - GEO my WP plugin <= 4.5.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9757
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9757
rules:
  - title: Detect CVE-2026-9757 Exploitation Attempt - GEO my WP SQL Injection
    description: Detects CVE-2026-9757 exploitation attempt - SQL injection via crafted swlatlng or nelatlng parameters in GEO my WP plugin requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect WordPress Requests Bypassing wp_magic_quotes
    description: Detects requests to WordPress bypassing the now-deprecated wp_magic_quotes protection using $_SERVER['QUERY_STRING'].
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The GEO my WP plugin, a WordPress plugin designed for location-based functionality, contains a SQL injection vulnerability (CVE-2026-9757) in versions up to and including 4.5.5. The vulnerability lies within the handling of the 'swlatlng' and 'nelatlng' parameters, which are used to define geographical boundaries for searches. These parameters are extracted from the `$_SERVER['QUERY_STRING']` array using `parse_str()`, bypassing the standard WordPress magic quotes protection, and are subsequently incorporated into a SQL query without proper sanitization or validation. This flaw enables unauthenticated attackers to inject arbitrary SQL code into the query, potentially leading to the extraction of sensitive data from the WordPress database. Successful exploitation requires the presence of the `[gmw form="results" form_id=N]` shortcode on a publicly accessible page and at least one post with an associated `gmw_location` entry.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP request targeting a WordPress page containing the `[gmw form="results" form_id=N]` shortcode.
2. The malicious request includes the `swlatlng` and/or `nelatlng` parameters in the URL's query string, containing SQL injection payloads.
3. WordPress's `parse_str()` function parses the query string from `$_SERVER['QUERY_STRING']`, extracting the injected parameters. Critically, this bypasses `wp_magic_quotes` protection.
4. The `gmw_get_locations_within_boundaries_sql()` function receives the unsanitized `swlatlng` and `nelatlng` parameters.
5. The `explode()` function splits the parameters by commas, creating fragments.
6. These fragments are directly interpolated into a SQL `BETWEEN` clause within the `gmw_get_locations_within_boundaries_sql()` function without any validation (e.g. `is_numeric()`), casting to float, or sanitization (e.g. `esc_sql()` or `$wpdb->prepare()`).
7. The injected SQL code is executed against the WordPress database.
8. The attacker extracts sensitive information, such as user credentials or other plugin data, from the database using the injected SQL queries.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-9757) allows unauthenticated attackers to execute arbitrary SQL queries against the WordPress database. This can lead to the disclosure of sensitive information, including user credentials, database configurations, and other confidential data stored within the database. A successful attack could compromise the entire WordPress installation and potentially any other applications sharing the same database server. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high severity.

## Recommendation

*   Upgrade the GEO my WP plugin to the latest version, which includes a fix for CVE-2026-9757.
*   Deploy the Sigma rule "Detect CVE-2026-9757 Exploitation Attempt - GEO my WP SQL Injection" to your SIEM to detect exploitation attempts based on suspicious query string parameters.
*   Monitor web server logs for requests containing the `swlatlng` and `nelatlng` parameters in the query string with SQL injection syntax, as detected by the Sigma rule above.
