---
title: 'CVE-2026-18881: SQL Injection in TableOn WordPress Plugin'
slug: 2026-08-tableon-sqli
description: An unauthenticated SQL injection vulnerability in the TableOn WordPress plugin allows attackers to extract sensitive database information via the filter_data[comment_count] parameter.
date: "2026-08-05T11:15:39Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - TableOn – WordPress Posts Table Filterable (<= 1.0.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can append additional SQL queries into the already-existing query that can be used to extract sensitive information.
    confidence_band: high
cves:
  - id: CVE-2026-18881
    cvss: 7.5
rules:
  - title: Detects CVE-2026-18881 Exploitation - SQL Injection via TableOn Plugin
    description: Detects exploitation attempts against the TableOn plugin by monitoring for suspicious SQL injection syntax within the filter_data[comment_count] parameter in AJAX requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update TableOn plugin to the version containing the security patch.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 1.0.5.1
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to filter traffic to the tableon_get_table_data AJAX action.
      owner: Security Operations
      addresses: CVE-2026-18881
      evidence: Plugin vulnerable to unauthenticated SQL injection
---

The TableOn - WordPress Posts Table Filterable plugin for WordPress is vulnerable to a blind SQL injection vulnerability identified as CVE-2026-18881. This flaw affects all versions up to and including 1.0.5.1. The vulnerability exists within the public `tableon_get_table_data` AJAX action, specifically due to improper handling of the `filter_data[comment_count]` parameter. The plugin fails to apply necessary input validation or sanitization, such as `intval()` casting, and fails to use the `$wpdb->prepare()` function when processing this parameter. Consequently, the input is interpolated directly into a `posts_where` SQL clause after being split by a colon delimiter. Unauthenticated attackers can leverage this flaw to append malicious SQL commands, enabling them to execute blind SQL injection attacks to exfiltrate sensitive data from the WordPress database, including entries from the `wp_users` table.

## Impact

Successful exploitation allows unauthenticated remote attackers to perform blind SQL injection against the host WordPress site. Potential consequences include the exfiltration of sensitive information, such as administrator hashes or user credentials, which could lead to complete site compromise. Given the prevalence of WordPress plugins in enterprise environments, this poses a high risk to sites utilizing the TableOn plugin.

## Recommendation

- Upgrade the TableOn - WordPress Posts Table Filterable plugin to the latest version released after August 5, 2026, which contains the security patch for CVE-2026-18881.
- Implement a Web Application Firewall (WAF) rule to inspect and block incoming HTTP requests targeting the `tableon_get_table_data` action where the `filter_data[comment_count]` parameter contains SQL-specific characters or patterns.
- Audit database query logs for suspicious patterns originating from external IP addresses targeting the affected AJAX endpoint.
