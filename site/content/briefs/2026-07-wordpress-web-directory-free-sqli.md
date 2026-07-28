---
title: Generic SQL Injection Vulnerability in WordPress Web Directory Free Plugin (CVE-2026-14785)
slug: 2026-07-wordpress-web-directory-free-sqli
description: The Web Directory Free plugin for WordPress, in all versions up to and including 1.7.13, is vulnerable to generic SQL Injection through the 'levels' parameter. This flaw, caused by insufficient input escaping and lack of query preparation, enables unauthenticated attackers to append arbitrary SQL queries to existing ones, allowing them to extract sensitive information directly from the database.
date: "2026-07-28T10:21:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - plugin
  - web
  - cve
vendors:
  - mihail-chepovskiy
products:
  - Web Directory Free (<= 1.7.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated attackers to append additional SQL queries into already existing queries
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: can be used to extract sensitive information from the database
    confidence_band: high
cves:
  - id: CVE-2026-14785
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14785
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/7320421b-6b88-452d-a363-a71cdf7953a6?source=cve
rules:
  - title: Detects CVE-2026-14785 Exploitation - WordPress Web Directory Free SQL Injection
    description: Detects exploitation attempts for CVE-2026-14785, a generic SQL Injection vulnerability in the Web Directory Free WordPress plugin, via suspicious patterns in the 'levels' parameter of HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL Injection vulnerability, tracked as CVE-2026-14785, has been identified in the Web Directory Free plugin for WordPress, affecting all versions up to and including 1.7.13. This flaw stems from insufficient escaping of user-supplied input to the 'levels' parameter and inadequate preparation of existing SQL queries. The vulnerability allows unauthenticated attackers to inject malicious SQL code, appending it to legitimate database queries. Successful exploitation can lead to the extraction of sensitive information from the underlying database, such as user credentials, personal data, or configuration details. This presents a significant risk to the confidentiality of data hosted on affected WordPress sites.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP GET or POST request targeting a vulnerable endpoint of the WordPress Web Directory Free plugin.
2. The attacker includes a specially crafted SQL injection payload within the 'levels' parameter of the HTTP request.
3. The vulnerable plugin, due to inadequate input sanitization, processes the request and appends the attacker's SQL payload to an existing database query.
4. The manipulated query is sent to the WordPress database, where the malicious SQL commands are executed.
5. The database processes the injected query, which could be designed to select, union, or otherwise retrieve sensitive data from tables.
6. The results of the malicious query, including the extracted sensitive information, are returned in the HTTP response to the attacker.
7. The attacker parses the HTTP response to collect the sensitive data.

## Impact

Successful exploitation of CVE-2026-14785 can lead to unauthorized access and exfiltration of sensitive information stored in the WordPress database. This could include user credentials (usernames and hashed passwords), personal identifiable information (PII) of registered users, configuration settings, and other proprietary data. The compromise of such data can result in significant financial, reputational, and regulatory damage for organizations utilizing the vulnerable plugin. While no specific victim numbers or targeted sectors are mentioned, any WordPress site using the Web Directory Free plugin up to version 1.7.13 is susceptible.

## Recommendation

* Immediately update the Web Directory Free plugin for WordPress to a version patched against CVE-2026-14785.
* Deploy the Sigma rule "Detects CVE-2026-14785 Exploitation - WordPress Web Directory Free SQL Injection" to your SIEM to detect exploitation attempts.
* Configure web server logging (e.g., Apache, Nginx, IIS) to capture `cs-uri-stem` and `cs-uri-query` for all HTTP requests to aid in detecting and investigating web-based attacks.
