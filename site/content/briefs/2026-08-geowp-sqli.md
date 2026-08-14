---
title: Unauthenticated SQL Injection in GEO my WordPress Plugin
slug: 2026-08-geowp-sqli
description: An unauthenticated SQL injection vulnerability (CVE-2026-52715) in the GEO my WordPress plugin allows attackers to exfiltrate database contents via malicious query parameters.
date: "2026-08-14T21:22:19Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - GEO my WP
products:
  - GEO my WordPress (< 4.5.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated SQL injection in GEO my WP via parse_str of unsanitized query params into BETWEEN clause.
    confidence_band: high
cves:
  - id: CVE-2026-52715
    cvss: 9.3
    epss: 0.00243
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-52715
  - https://patchstack.com/database/wordpress/plugin/geo-my-wp/vulnerability/wordpress-geo-my-wordpress-plugin-4-5-5-sql-injection-vulnerability
rules:
  - title: Detect CVE-2026-52715 SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting GEO my WordPress via 'swlatlng' or 'nelatlng' parameters in the query string
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-52715 is a high-severity unauthenticated SQL injection vulnerability affecting the GEO my WordPress plugin versions prior to 4.5.5.1. The flaw exists due to improper handling of user-supplied query parameters, specifically 'swlatlng' and 'nelatlng', which are passed through the 'parse_str' function and subsequently interpolated into a SQL 'BETWEEN' clause within the 'gmw_get_locations_within_boundaries_sql' function. An attacker can exploit this via crafted GET requests to perform blind time-based or boolean-based SQL injection, potentially leading to the full exfiltration of the WordPress database, including user credentials. A public proof-of-concept exploit was released on August 14, 2026, significantly increasing the risk of exploitation.

## Attack Chain

1. The attacker identifies a public-facing WordPress page utilizing the GEO my WordPress shortcode [gmw form="1"].
2. The attacker crafts a malicious HTTP GET request targeting the page, appending or modifying query parameters 'swlatlng' or 'nelatlng'.
3. The plugin's 'GMW_Form::set_default_values' method processes the 'QUERY_STRING' and passes it to 'gmw_get_form_values'.
4. The 'gmw_get_form_values' function uses 'parse_str' on the input without an allowlist, allowing the malicious 'swlatlng' or 'nelatlng' parameters to persist.
5. The 'parse_query_args' function copies these parameters into the search arguments used by the database query builder.
6. The 'gmw_get_locations_within_boundaries_sql' function performs direct string interpolation of the tainted input into a SQL 'BETWEEN' clause.
7. The 'WP_Query' object executes the resulting 'get_results' call, triggering the injection against the MariaDB backend.
8. The attacker observes application response times (time-based) or changes in the 'total_results' JSON field (boolean-based) to exfiltrate database records.

## Impact

The vulnerability allows unauthenticated attackers to read sensitive database records. Successful exploitation can lead to full compromise of the WordPress site, including the exfiltration of user account information, administrative hashes, and other sensitive site configuration data. The vulnerability is rated CVSS 9.3.

## Recommendation

* Immediately update the GEO my WordPress plugin to version 4.5.5.1 or higher to incorporate the patch.
* Deploy a WAF rule to inspect incoming HTTP GET requests for non-numeric, suspicious characters in the 'swlatlng' and 'nelatlng' query parameters.
* Review web server logs for request patterns containing 'swlatlng=' or 'nelatlng=' followed by SQL syntax (e.g., 'SLEEP', 'CASE', 'WHEN', 'THEN').
* If compromise is suspected, initiate incident response procedures, rotate administrative credentials, and audit database user activity.
