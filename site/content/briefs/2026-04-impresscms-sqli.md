---
title: ImpressCMS 1.3.11 Time-Based Blind SQL Injection Vulnerability
slug: 2026-04-impresscms-sqli
description: ImpressCMS 1.3.11 contains a time-based blind SQL injection vulnerability allowing authenticated attackers to manipulate database queries by injecting SQL code through the 'bid' parameter via POST requests to the admin.php endpoint.
date: "2026-04-12T13:16:33Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - impresscms
  - cve-2019-25703
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25703
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25703
  - http://www.impresscms.org/
  - https://sourceforge.net/projects/impresscms/files/v1.3.11/impresscms_1.3.11.zip
  - https://www.exploit-db.com/exploits/46239
  - https://www.vulncheck.com/advisories/impresscms-sql-injection-via-bid-parameter
iocs:
  - type: url
    value: http://www.impresscms.org/
  - type: url
    value: https://sourceforge.net/projects/impresscms/files/v1.3.11/impresscms_1.3.11.zip
  - type: url
    value: https://www.exploit-db.com/exploits/46239
  - type: url
    value: https://www.vulncheck.com/advisories/impresscms-sql-injection-via-bid-parameter
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect ImpressCMS SQL Injection Attempt via bid Parameter
    description: Detects potential SQL injection attempts in ImpressCMS admin.php via the 'bid' parameter based on common SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ImpressCMS SQL Injection Attempt via bid Parameter - Error Based
    description: Detects potential SQL injection attempts in ImpressCMS admin.php via the 'bid' parameter based on common SQL error generation syntax.
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

ImpressCMS is an open-source content management system. Version 1.3.11 is vulnerable to a time-based blind SQL injection vulnerability (CVE-2019-25703). An authenticated attacker can exploit this vulnerability by injecting malicious SQL code into the 'bid' parameter. Successful exploitation allows the attacker to manipulate database queries, potentially leading to the extraction of sensitive information. This vulnerability requires authentication, limiting the scope of potential attackers, but the impact can be severe if exploited successfully. The vulnerability was reported and disclosed in April 2026.

## Attack Chain

1. The attacker authenticates to the ImpressCMS application with valid credentials.
2. The attacker crafts a malicious POST request targeting the `admin.php` endpoint.
3. The POST request includes the `bid` parameter containing SQL injection payload designed to cause a time delay.
4. The ImpressCMS application processes the POST request without proper sanitization of the `bid` parameter.
5. The injected SQL code is executed against the underlying database, causing a time-based delay.
6. The attacker monitors the response time to confirm successful injection.
7. The attacker refines the SQL injection payload to extract sensitive information from the database using techniques like `SLEEP()` and conditional queries.
8. The attacker exfiltrates the sensitive data obtained from the database.

## Impact

Successful exploitation of this vulnerability allows an attacker to read sensitive data from the ImpressCMS database. This may include user credentials, configuration details, and other confidential information. While the exploit requires authentication, a successful attack could lead to complete compromise of the application and its data, potentially impacting all users and the integrity of the website. The CVSS v3.1 score of 7.1 reflects the high potential impact of this vulnerability.

## Recommendation

*   Apply the necessary patches or upgrade to a version of ImpressCMS that addresses CVE-2019-25703 to remediate the SQL injection vulnerability.
*   Deploy the provided Sigma rule to detect malicious POST requests containing SQL injection attempts targeting the `admin.php` endpoint.
*   Implement input validation and sanitization on the `bid` parameter within the ImpressCMS application to prevent SQL injection attacks.
*   Monitor web server logs for suspicious POST requests to `admin.php` with unusual parameters, as this can be an indicator of exploitation attempts.
*   Review and restrict access to the `admin.php` endpoint to only authorized users to minimize the attack surface.
