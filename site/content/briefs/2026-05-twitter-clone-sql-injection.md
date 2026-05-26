---
title: Twitter-Clone 1 SQL Injection Vulnerability (CVE-2018-25362)
slug: 2026-05-twitter-clone-sql-injection
description: Twitter-Clone 1 is vulnerable to SQL injection via the userid parameter in follow.php, allowing attackers to manipulate database queries and extract sensitive information such as usernames, passwords, and database credentials.
date: "2026-05-26T14:13:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqlinjection
  - cve
  - webapp
products:
  - Twitter-Clone 1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25362
    cvss: 8.2
    epss: 0.00033
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25362
  - https://github.com/Fyffe/PHP-Twitter-Clone/
  - https://www.exploit-db.com/exploits/45230
  - https://www.vulncheck.com/advisories/twitter-clone-1-sql-injection-via-follow-php
rules:
  - title: Detect SQL Injection Attempt via follow.php
    description: Detects SQL injection attempts targeting follow.php via the userid parameter (CVE-2018-25362)
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SQL Error Messages in Web Responses
    description: Detects SQL error messages in web server responses, which can indicate a successful SQL injection.
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

Twitter-Clone 1 is susceptible to SQL injection within the follow.php script. This vulnerability allows a remote, unauthenticated attacker to inject arbitrary SQL commands into the `userid` parameter. Successful exploitation enables attackers to manipulate database queries, potentially leading to the extraction of sensitive information, including usernames, passwords, and database credentials. This poses a significant risk to the confidentiality and integrity of the application and its user data. The vulnerability was reported on 2026-05-25.

## Attack Chain

1.  Attacker identifies the vulnerable `follow.php` script.
2.  Attacker crafts a malicious HTTP request targeting `follow.php` with a SQL injection payload in the `userid` parameter. Example: `follow.php?userid=1' UNION SELECT username, password FROM users -- -`.
3.  The web server processes the request, and the vulnerable application executes the attacker-supplied SQL query against the database.
4.  The database server executes the malicious SQL query, potentially returning sensitive data.
5.  The application displays the results of the malicious query, leaking database content, such as usernames and password hashes, back to the attacker.
6.  The attacker analyzes the leaked data, potentially using it to compromise user accounts.
7.  The attacker may use the extracted database credentials to gain unauthorized access to the database server itself.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25362) could lead to unauthorized access to sensitive data, including usernames, passwords, and database credentials. This could allow an attacker to compromise user accounts, gain unauthorized access to the database server, and potentially compromise the entire application and its underlying infrastructure. The number of potential victims is limited to the number of users of the Twitter-Clone 1 application.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to all user-supplied data, particularly within the `follow.php` script, to prevent SQL injection attacks.
*   Deploy the Sigma rule to detect SQL injection attempts targeting the `follow.php` endpoint (see rule: "Detect SQL Injection Attempt via follow.php").
*   Implement the principle of least privilege for database access, ensuring that the application only has the necessary permissions to perform its intended functions.
*   Monitor web server logs for suspicious activity, such as unusual characters or SQL keywords in URL parameters.
*   Consider using parameterized queries or prepared statements to prevent SQL injection vulnerabilities.
