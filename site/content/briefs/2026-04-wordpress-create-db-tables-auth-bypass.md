---
title: WordPress Create DB Tables Plugin Authorization Bypass Vulnerability (CVE-2026-4119)
slug: 2026-04-wordpress-create-db-tables-auth-bypass
description: The Create DB Tables plugin for WordPress versions 1.2.1 and earlier is vulnerable to an authorization bypass, allowing authenticated users to create and delete database tables without proper checks, potentially leading to complete site destruction.
date: "2026-04-22T09:16:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - authorization-bypass
  - plugin-vulnerability
  - cve-2026-4119
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-4119
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4119
rules:
  - title: Detect Unauthorized DB Table Modification
    description: Detects POST requests to wp-admin/admin-post.php with actions related to database table manipulation, indicating potential unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: WAF - Block Unauthorized DB Table Modification
    description: This rule detects and blocks POST requests to wp-admin/admin-post.php with actions related to database table manipulation if not originating from an admin IP address.
    platform: sigma
    severity: critical
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - firewall
      - linux
rules_count: 2
---

The Create DB Tables plugin, versions 1.2.1 and earlier, suffers from an authorization bypass vulnerability (CVE-2026-4119). This flaw stems from the plugin's failure to implement capability checks or nonce verification for its admin_post action hooks, specifically those responsible for creating (admin_post_add_table) and deleting (admin_post_delete_db_table) database tables. Because the admin_post hook only requires a user to be logged in, any authenticated user, including those with the lowest Subscriber role, can access these endpoints. This oversight allows malicious actors to create arbitrary database tables or, more critically, delete existing ones, including vital WordPress core tables. The vulnerability was published on 2026-04-22, and given the severity, defenders should immediately address this risk. The affected versions of the plugin should be updated or removed to prevent potential exploitation.

## Attack Chain

1. An attacker registers an account on a vulnerable WordPress site, gaining Subscriber-level access.
2. The attacker crafts a POST request to `wp-admin/admin-post.php` with the action parameter set to `add_table` or `delete_db_table`.
3. The attacker provides the `db_table` parameter with the name of the table to be deleted, if exploiting the `delete_db_table` action.
4. The server processes the request without proper authorization checks, because `current_user_can()` and `wp_verify_nonce()` are missing.
5. The `cdbt_delete_db_table()` function executes a `DROP TABLE` SQL query based on the user-supplied `db_table` parameter.
6. If the attacker targets a critical WordPress core table like `wp_users` or `wp_options`, the site's functionality will be severely impacted.
7. Alternatively, if exploiting the `add_table` action, the `cdbt_create_new_table()` function executes a `CREATE TABLE` SQL query, creating an arbitrary database table.
8. Successful exploitation can lead to complete destruction of the WordPress installation or the introduction of malicious database tables.

## Impact

Successful exploitation of this vulnerability allows any authenticated user to delete arbitrary database tables, including critical WordPress core tables. This can lead to complete site destruction and data loss. An attacker could delete the `wp_users` table, effectively locking out all administrators and other users, or delete the `wp_options` table, causing the site to revert to its default state or become completely unusable. The CVSS v3.1 base score for this vulnerability is 9.1, highlighting the critical nature of the risk.

## Recommendation

*   Immediately update the Create DB Tables plugin to a version higher than 1.2.1, where this vulnerability is patched.
*   Monitor web server logs for POST requests to `wp-admin/admin-post.php` with `action=delete_db_table` or `action=add_table` (see rule: "Detect Unauthorized DB Table Modification").
*   Implement a Web Application Firewall (WAF) rule to block requests to `wp-admin/admin-post.php` with the vulnerable actions unless originating from an administrator (see rule: "WAF - Block Unauthorized DB Table Modification").
