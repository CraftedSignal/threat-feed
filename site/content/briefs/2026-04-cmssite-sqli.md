---
title: CMSsite 1.0 SQL Injection Vulnerability (CVE-2019-25697)
slug: 2026-04-cmssite-sqli
description: CMSsite 1.0 is vulnerable to unauthenticated SQL injection (CVE-2019-25697) via the cat_id parameter in category.php, allowing attackers to extract sensitive database information.
date: "2026-04-12T13:16:32Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - cve-2019-25697
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1211
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2019-25697
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25697
  - https://github.com/VictorAlagwu/CMSsite/archive/master.zip
  - https://www.exploit-db.com/exploits/46259
  - https://www.vulncheck.com/advisories/cmssite-sql-injection-via-category-php
rules:
  - title: Detect Suspicious GET Requests to category.php with SQL Injection Attempts
    description: Detects GET requests to category.php with potential SQL injection attempts based on common SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
  - title: Detect SQL error messages in web server logs
    description: Detects SQL error messages in web server logs indicating potential SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CMSsite 1.0 is susceptible to an SQL injection vulnerability (CVE-2019-25697) within the category.php script. This flaw allows unauthenticated, remote attackers to inject arbitrary SQL commands by manipulating the `cat_id` GET parameter. Successful exploitation could lead to the disclosure of sensitive information stored within the database, including user credentials and other application data. Given the ease of exploitation and the potential impact, this vulnerability poses a significant risk to organizations using the affected CMSsite version. The vulnerability was reported to NVD and assigned a CVSS v3.1 score of 8.2, indicating high severity.

## Attack Chain

1.  The attacker identifies a CMSsite 1.0 installation.
2.  The attacker crafts a malicious HTTP GET request targeting `category.php`.
3.  The attacker injects SQL code into the `cat_id` parameter of the GET request, for example: `category.php?cat_id=1' OR '1'='1`.
4.  The web server processes the request and passes the tainted `cat_id` value to the underlying SQL database.
5.  The injected SQL code manipulates the database query, potentially bypassing intended security checks.
6.  The database executes the modified query, returning sensitive data to the web server.
7.  The web server includes the extracted data in the HTTP response.
8.  The attacker parses the HTTP response to extract sensitive information such as usernames, passwords, or other confidential data.

## Impact

Successful exploitation of this SQL injection vulnerability allows an unauthenticated attacker to read sensitive information from the CMSsite 1.0 database. This can lead to complete compromise of the application, including unauthorized access to user accounts, exposure of confidential data, and potential further attacks on the underlying system. Given the lack of required authentication, any CMSsite 1.0 instance exposed to the internet is a potential target.

## Recommendation

*   Apply appropriate input validation and sanitization to the `cat_id` parameter in `category.php` to prevent SQL injection.
*   Deploy the Sigma rule "Detect Suspicious GET Requests to category.php with SQL Injection Attempts" to identify exploitation attempts in web server logs.
*   Restrict database access privileges to the minimum necessary for the application to function.
*   Consider upgrading to a more secure CMS solution or applying a patch if one becomes available.
*   Enable web server logging and monitor for unusual activity, paying close attention to GET requests targeting `category.php`.
*   Implement parameterized queries or prepared statements to prevent SQL injection vulnerabilities when interacting with the database.
