---
title: Matrimony Website Script M-Plus SQL Injection Vulnerabilities
slug: 2024-01-matrimony-sqli
description: Matrimony Website Script M-Plus is vulnerable to unauthenticated SQL injection via POST parameters, enabling attackers to extract sensitive data or execute arbitrary SQL commands.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - Matrimony Website Script M-Plus
products:
  - Matrimony Website Script M-Plus
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25639
rules:
  - title: Detect SQL Injection Attempts via POST Parameters
    description: Detects potential SQL injection attempts in POST requests to vulnerable PHP files by looking for SQL syntax in common parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via Error Messages
    description: Detects SQL injection by monitoring HTTP error responses containing SQL-related keywords.
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

The Matrimony Website Script M-Plus is susceptible to multiple SQL injection vulnerabilities (CVE-2019-25639) that allow unauthenticated attackers to inject malicious SQL code. This vulnerability allows threat actors to potentially extract sensitive data from the database or execute arbitrary SQL commands. The vulnerability is located in multiple PHP files, including simplesearch_results.php, advsearch_results.php, specialcase_results.php, locational_results.php, and registration2.php. This poses a significant risk to organizations using this software, as attackers could gain unauthorized access to user data, modify website content, or compromise the entire system. The exploitation of this vulnerability requires no authentication.

## Attack Chain

1.  An unauthenticated attacker identifies a Matrimony Website Script M-Plus instance.
2.  The attacker crafts a malicious HTTP POST request targeting one of the vulnerable PHP files: simplesearch_results.php, advsearch_results.php, specialcase_results.php, locational_results.php, or registration2.php.
3.  The attacker injects SQL code into one or more of the following parameters: txtGender, religion, Fage, or cboCountry.
4.  The web server processes the malicious POST request, passing the injected SQL code to the database server without proper sanitization or input validation.
5.  The database server executes the injected SQL code, potentially allowing the attacker to extract sensitive data (e.g., user credentials, personal information) using SQL injection techniques like UNION-based injection.
6.  Alternatively, the attacker could execute arbitrary SQL commands to modify data, create new accounts, or potentially gain control over the database server.
7.  The attacker retrieves the results of the SQL query from the web server's response.
8.  The attacker uses the extracted data or control over the database to further compromise the system.

## Impact

Successful exploitation of these SQL injection vulnerabilities could lead to the complete compromise of the Matrimony Website Script M-Plus instance. Attackers could gain unauthorized access to sensitive user data, including personal details, contact information, and potentially financial data. This could result in identity theft, financial fraud, and reputational damage for both the website operator and its users. The impact is significant given the potential for widespread data breaches and the high CVSS score of 8.2.

## Recommendation

*   Inspect web server logs for suspicious POST requests targeting simplesearch_results.php, advsearch_results.php, specialcase_results.php, locational_results.php, and registration2.php, especially those containing SQL syntax in the txtGender, religion, Fage, or cboCountry parameters to detect potential exploitation attempts (see the rules below).
*   Apply any available patches or updates for Matrimony Website Script M-Plus to address CVE-2019-25639.
*   Implement proper input validation and sanitization techniques to prevent SQL injection vulnerabilities in the Matrimony Website Script M-Plus, especially for the txtGender, religion, Fage, and cboCountry parameters.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
