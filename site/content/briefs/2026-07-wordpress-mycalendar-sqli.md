---
title: CVE-2026-6854 - WordPress My Calendar Plugin Time-Based Blind SQL Injection
slug: 2026-07-wordpress-mycalendar-sqli
description: A time-based blind SQL Injection vulnerability exists in the My Calendar - Accessible Event Manager plugin for WordPress, affecting all versions up to and including 3.7.8. This flaw, located in the 'mc_auth' parameter, stems from insufficient input sanitization and improper SQL query preparation, allowing unauthenticated attackers to inject additional SQL queries to extract sensitive information from the underlying database.
date: "2026-07-08T12:21:22Z"
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
  - collection
  - initial-access
vendors:
  - My Calendar
  - WordPress
products:
  - My Calendar - Accessible Event Manager plugin <= 3.7.8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The My Calendar – Accessible Event Manager plugin for WordPress is vulnerable to time-based blind SQL Injection via the 'mc_auth' parameter in all versions up to, and including, 3.7.8 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1565
    technique_name: Stolen Data
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
    confidence_band: high
cves:
  - id: CVE-2026-6854
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6854
rules:
  - title: Detects CVE-2026-6854 Exploitation - My Calendar Plugin Time-Based Blind SQLi
    description: Detects CVE-2026-6854 exploitation - Unauthenticated time-based blind SQL Injection attempts targeting the 'mc_auth' parameter in My Calendar WordPress plugin, using common delay functions.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
      - T1565.001
    data_sources:
      - webserver
rules_count: 1
---

The My Calendar - Accessible Event Manager plugin for WordPress is affected by CVE-2026-6854, a critical time-based blind SQL Injection vulnerability. This flaw impacts all versions of the plugin up to and including 3.7.8. The vulnerability originates from insufficient input sanitization of the `mc_auth` parameter and inadequate preparation of existing SQL queries. This allows unauthenticated attackers to append malicious SQL statements, enabling them to illicitly extract sensitive data from the underlying database. The vulnerability poses a significant risk to the confidentiality of information stored on affected WordPress sites. Attackers can leverage this to gain unauthorized access to user data, configuration details, and other proprietary information, leading to potential data breaches and compliance issues.

## Attack Chain

1. **Initial Access**: An unauthenticated attacker identifies a WordPress site running the vulnerable My Calendar plugin (version 3.7.8 or below).
2. **Reconnaissance**: The attacker analyzes HTTP requests related to the My Calendar plugin, specifically identifying the `mc_auth` parameter.
3. **Payload Crafting**: The attacker constructs a malicious time-based blind SQL Injection payload designed to interact with the database through the `mc_auth` parameter. This payload typically includes database functions like `SLEEP()` or `WAITFOR DELAY` combined with conditional statements to infer information character by character.
4. **Exploitation Request**: The attacker sends a specially crafted HTTP GET or POST request to the vulnerable WordPress endpoint, embedding the SQL injection payload within the `mc_auth` parameter.
5. **Database Interaction**: The WordPress application processes the request, and due to insufficient sanitization, the malicious SQL payload is executed by the backend database.
6. **Information Exfiltration**: By observing the response times of multiple such requests, the attacker can systematically infer characters of the database content (e.g., user credentials, sensitive configurations) without direct error messages or visible output.
7. **Data Collection**: The attacker continues this process to extract specific sensitive information, such as administrator hashes, API keys, or customer data, from the database.
8. **Impact**: The extracted sensitive data can then be used for further attacks, identity theft, or sold on illicit markets, leading to severe data breaches and financial/reputational damage.

## Impact

Successful exploitation of CVE-2026-6854 allows unauthenticated attackers to extract sensitive information from the affected WordPress site's database. This includes, but is not limited to, user credentials, personal identifiable information (PII), configuration details, and other proprietary data. The impact on victims is severe, potentially leading to widespread data breaches, financial losses due to regulatory fines or remediation efforts, and significant reputational damage. While no specific victim counts are available, the broad adoption of WordPress plugins suggests a substantial number of organizations could be at risk if they are using the vulnerable plugin version.

## Recommendation

* **Patch CVE-2026-6854**: Immediately update the My Calendar - Accessible Event Manager plugin to version 3.7.9 or later to remediate CVE-2026-6854.
* **Deploy WAF Rules**: Implement and tune Web Application Firewall (WAF) rules to detect and block SQL Injection attempts, especially those targeting common SQL functions like `SLEEP` or `WAITFOR DELAY` within URI queries or POST bodies.
* **Monitor Web Logs**: Deploy the Sigma rule below to your SIEM to detect potential exploitation attempts for CVE-2026-6854 by monitoring web server access logs for suspicious patterns in the `mc_auth` parameter.
