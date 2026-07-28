---
title: WordPress PickPlugins Question Answer Plugin SQL Injection Vulnerability (CVE-2026-10207)
slug: 2026-07-pickplugins-sql-injection
description: An unauthenticated SQL injection vulnerability, tracked as CVE-2026-10207, exists in the PickPlugins Question Answer plugin for WordPress versions up to and including 1.2.73, allowing attackers to extract sensitive database information due to insufficient input sanitization of the 'id' GET parameter and improper SQL query construction.
date: "2026-07-28T10:19:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - PickPlugins
  - WordPress
products:
  - Question Answer plugin <= 1.2.73
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The PickPlugins Question Answer plugin for WordPress is vulnerable to SQL Injection... This makes it possible for unauthenticated attackers to append additional SQL queries into existing queries...
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This is due to insufficient sanitization of user-supplied input via the 'id' GET parameter... combined with the use of wp_unslash() ... followed by direct concatenation into a SQL query... which can be used to extract sensitive information from the database.
    confidence_band: high
cves:
  - id: CVE-2026-10207
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10207
rules:
  - title: Detects CVE-2026-10207 Exploitation - WordPress PickPlugins Question Answer SQLi
    description: Detects exploitation attempts for CVE-2026-10207, an unauthenticated SQL Injection vulnerability in the PickPlugins Question Answer plugin for WordPress. The rule looks for malicious patterns in the 'id' GET parameter within HTTP GET requests targeting common plugin endpoints.
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

A critical SQL injection vulnerability, identified as CVE-2026-10207, has been discovered in the PickPlugins Question Answer plugin for WordPress, affecting all versions up to and including 1.2.73. This flaw permits unauthenticated attackers to exploit insufficient sanitization of the 'id' GET parameter within the user profile template. The vulnerability is compounded by the plugin's use of `wp_unslash()` which bypasses WordPress's native magic quotes protection, leading to direct concatenation of user-supplied input into a SQL query within the `qa_user_profile_card()` function without proper escaping or prepared statements. This weakness enables attackers to append arbitrary SQL queries, potentially facilitating the extraction of sensitive information from the underlying database. The vulnerability does not require prior authentication, making it a severe risk for affected WordPress installations.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP GET request targeting a WordPress site running the vulnerable PickPlugins Question Answer plugin.
2. The request is directed at a URL associated with the plugin's user profile template, including a specially crafted `id` GET parameter.
3. The WordPress application receives the request and the PickPlugins Question Answer plugin's `qa_user_profile_card()` function processes the `id` parameter.
4. The plugin utilizes `wp_unslash()` on the user-supplied `id` parameter, inadvertently removing any WordPress-provided magic quotes protection.
5. The unsanitized and unescaped `id` parameter is then directly concatenated into a SQL query within the plugin's backend code.
6. The malicious SQL payload embedded in the `id` parameter modifies the original query, allowing the attacker to execute arbitrary SQL commands.
7. The database executes the attacker's appended SQL queries.
8. Sensitive information, such as user data, configuration details, or other database contents, is extracted and returned to the attacker.

## Impact

Successful exploitation of CVE-2026-10207 allows unauthenticated attackers to perform SQL injection. The primary impact is the unauthorized disclosure of sensitive data stored in the WordPress database. This could include user credentials (hashed or plaintext), personal information, website configuration details, and other proprietary data, leading to severe privacy breaches, potential account takeover, and further compromise of the WordPress site. While no specific victim counts or targeted sectors are provided, any organization or individual using the vulnerable plugin is at risk.

## Recommendation

* Immediately update the PickPlugins Question Answer plugin to a version greater than 1.2.73 to patch CVE-2026-10207.
* Deploy the Sigma rule in this brief to your SIEM to detect attempts to exploit CVE-2026-10207.
* Ensure web server access logs are collected and sent to your SIEM for analysis, as the rule relies on `webserver` logs.
