---
title: JetEngine WordPress Plugin SQL Injection Vulnerability (CVE-2026-4662)
slug: 2024-01-jetengine-sqli
description: The JetEngine plugin for WordPress is vulnerable to SQL Injection due to the `filtered_query` parameter being excluded from HMAC signature validation and the `prepare_where_clause()` method not sanitizing the `compare` operator, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - sqli
  - jetengine
  - cve-2026-4662
  - cloud
vendors:
  - Crocoblock
products:
  - JetEngine
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4662
rules:
  - title: Detect JetEngine SQL Injection Attempt via filtered_query
    description: Detects potential SQL injection attempts in the JetEngine plugin by monitoring requests to the admin-ajax.php endpoint with the 'listing_load_more' action and suspicious SQL syntax in the 'filtered_query' parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect JetEngine SQL Injection via prepare_where_clause compare operator
    description: Detects potential SQL injection attempts by monitoring POST requests that include suspicious SQL syntax within the compare operator of the prepare_where_clause in JetEngine SQL queries.
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

The JetEngine plugin for WordPress, versions up to and including 3.8.6.1, contains a SQL Injection vulnerability (CVE-2026-4662) within the `listing_load_more` AJAX action. The vulnerability stems from two primary issues: the `filtered_query` parameter is excluded from HMAC signature validation, and the `prepare_where_clause()` method in the SQL Query Builder fails to sanitize the `compare` operator. This combination allows unauthenticated attackers to inject malicious SQL queries. The vulnerability is exploitable if the target site utilizes a JetEngine Listing Grid with Load More enabled and employs a SQL Query Builder query. Successful exploitation could lead to the extraction of sensitive database information.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the JetEngine plugin with a Listing Grid and Load More functionality enabled, utilizing a SQL Query Builder query.
2. The attacker crafts a malicious HTTP request targeting the `wp-admin/admin-ajax.php` endpoint, using the `listing_load_more` AJAX action.
3. The crafted request includes a `filtered_query` parameter containing a SQL injection payload. This parameter bypasses HMAC signature validation because it's excluded from the validation process.
4. The `filtered_query` parameter is processed by the `prepare_where_clause()` method in the SQL Query Builder.
5. The unsanitized `compare` operator within the `prepare_where_clause()` method allows the injected SQL code to be concatenated into the SQL query.
6. The injected SQL code is executed against the WordPress database.
7. Sensitive information, such as user credentials or other confidential data, is extracted from the database.
8. The attacker uses the extracted information for unauthorized access or further malicious activities.

## Impact

Successful exploitation of this vulnerability (CVE-2026-4662) allows unauthenticated attackers to extract sensitive information from the WordPress database. The potential damage includes data breaches, unauthorized access to user accounts, and compromise of confidential business information. Given the widespread use of WordPress and the JetEngine plugin, a large number of websites are potentially vulnerable. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high severity.

## Recommendation

*   Apply the latest security patches provided by Crocoblock for the JetEngine plugin to remediate CVE-2026-4662.
*   Deploy the Sigma rule "Detect JetEngine SQL Injection Attempt via filtered_query" to your SIEM and tune for your environment.
*   Monitor web server logs for requests to `wp-admin/admin-ajax.php` with the action `listing_load_more` and suspicious characters within the `filtered_query` parameter to identify potential exploitation attempts.
