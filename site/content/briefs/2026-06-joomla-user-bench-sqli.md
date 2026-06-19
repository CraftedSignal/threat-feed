---
title: Joomla! User Bench Component SQL Injection (CVE-2017-20254)
slug: 2026-06-joomla-user-bench-sqli
description: An unauthenticated attacker can exploit CVE-2017-20254, an SQL injection vulnerability in the Joomla! Component User Bench 1.0, by sending crafted HTTP GET requests to extract sensitive database information including credentials and configuration data.
date: "2026-06-19T16:22:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - joomla
  - web-vulnerability
  - cve
vendors:
  - Gegabyte
products:
  - User Bench 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20254
  - http://www.gegabyte.org/
  - https://extensions.joomla.org/extensions/extension/directory-a-documentation/directory/user-bench/
  - https://www.exploit-db.com/exploits/43357
  - https://www.vulncheck.com/advisories/joomla-component-user-bench-sql-injection-via-userid
rules:
  - title: Detects CVE-2017-20254 Exploitation — Joomla! User Bench SQL Injection
    description: Detects exploitation attempts of CVE-2017-20254, an SQL injection in Joomla! User Bench component 1.0, via suspicious characters in the 'userid' parameter within a GET request.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1561.001
    data_sources:
      - webserver
rules_count: 1
---

CVE-2017-20254 identifies an SQL injection vulnerability in the Joomla! Component User Bench version 1.0. This flaw allows an unauthenticated attacker to execute arbitrary SQL queries against the underlying database. The vulnerability specifically lies in the `userid` parameter when accessed via the `option=com_userbench&view=detail` GET request to `index.php`. Attackers can inject malicious SQL code, enabling them to bypass authentication, extract sensitive information such as user credentials, hashed passwords, and critical configuration data from the database. This vulnerability poses a significant risk to the confidentiality and integrity of Joomla! installations running the affected component.

## Attack Chain

1.  **Initial Access (Web Request)**: An unauthenticated attacker sends a crafted HTTP GET request to a vulnerable Joomla! instance running the User Bench 1.0 component.
2.  **Vulnerability Exploitation (SQL Injection)**: The GET request targets `index.php` with parameters `option=com_userbench&view=detail&userid=`, where the `userid` parameter contains a malicious SQL injection payload (e.g., `' UNION SELECT user,password FROM jos_users-- -`).
3.  **Database Query Manipulation**: The vulnerable component processes the `userid` parameter without proper sanitization, leading to the attacker's SQL payload being directly appended and executed within the backend database query.
4.  **Information Disclosure**: The injected SQL query is designed to extract sensitive data from the database, such as user credentials (usernames, hashed passwords), configuration data, or other proprietary information.
5.  **Data Exfiltration**: The results of the malicious SQL query are returned within the HTTP response, allowing the attacker to exfiltrate the sensitive database information.
6.  **Impact (Potential)**: With the extracted credentials, the attacker could gain unauthorized access to the Joomla! administration panel or other connected systems, leading to further compromise, data modification, or service disruption.

## Impact

A successful exploitation of CVE-2017-20254 allows unauthenticated attackers to steal sensitive data from the affected Joomla! database. This includes user credentials, database schema, configuration settings, and other critical information. The compromise of credentials could lead to full administrative control over the Joomla! instance, enabling defacement, content manipulation, or the injection of malicious web shells for further system compromise. The severity of impact depends on the criticality of the data stored in the Joomla! database and its connectivity to other internal systems.

## Recommendation

*   Immediately remove or update the Joomla! Component User Bench to a version that patches CVE-2017-20254, as version 1.0 is vulnerable.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect exploitation attempts of CVE-2017-20254.
*   Ensure web server access logs are collected and ingested into your SIEM, specifically capturing full URI and query parameters, to allow the rules in this brief to function effectively.
*   Review web server logs for suspicious GET requests containing SQL injection payloads as described in the Attack Chain.
