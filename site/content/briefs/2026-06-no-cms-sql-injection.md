---
title: No-CMS 1.0 SQL Injection Vulnerability (CVE-2018-25431)
slug: 2026-06-no-cms-sql-injection
description: No-Cms 1.0 is vulnerable to SQL injection (CVE-2018-25431) in the order_by parameter of the manage_privilege export endpoint, allowing authenticated attackers to manipulate database queries and potentially extract sensitive information.
date: "2026-06-01T22:18:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25431
  - web-application
vendors:
  - goFrendiAsgard
products:
  - No-Cms 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25431
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25431
  - https://codeload.github.com/goFrendiAsgard/No-CMS/zip/master
  - https://github.com/goFrendiAsgard/No-CMS
  - https://www.exploit-db.com/exploits/45903
  - https://www.vulncheck.com/advisories/no-cms-sql-injection-via-order-by-parameter
rules:
  - title: Detect CVE-2018-25431 Exploitation Attempt - No-CMS SQL Injection via order_by Parameter
    description: Detects CVE-2018-25431 exploitation attempt - SQL injection in No-CMS 1.0 via the order_by parameter in POST requests to /nocms/main/manage_privilege/index/export
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect No-CMS admin panel access
    description: Detect access to No-CMS admin panel
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

No-CMS 1.0 is susceptible to an SQL injection vulnerability within the `order_by` parameter of the `/nocms/main/manage_privilege/index/export` endpoint. This flaw, identified as CVE-2018-25431, allows an authenticated attacker to inject arbitrary SQL code into database queries. Successful exploitation enables the attacker to extract sensitive information from the database. The vulnerability exists because the application fails to properly sanitize user-supplied input to the `order_by` parameter, leading to unintended execution of attacker-controlled SQL commands. Defenders should prioritize patching or mitigating this vulnerability to prevent unauthorized data access.

## Attack Chain

1.  An attacker authenticates to the No-CMS 1.0 application.
2.  The attacker crafts a malicious POST request targeting the `/nocms/main/manage_privilege/index/export` endpoint.
3.  The POST request includes a modified `order_by[0]` parameter containing malicious SQL code.
4.  The application receives the request and processes the `order_by[0]` parameter without proper sanitization.
5.  The unsanitized SQL code is injected into a database query executed by the application.
6.  The attacker's injected SQL code manipulates the query to extract sensitive information.
7.  The database executes the modified query and returns the results to the application.
8.  The application displays or otherwise exposes the extracted sensitive information to the attacker.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25431) can lead to unauthorized access to sensitive data stored in the No-CMS database. This may include user credentials, personal information, financial records, or other confidential data. The impact of this vulnerability is high, as it allows an attacker with low privileges (authenticated user) to potentially compromise the entire database.

## Recommendation

*   Apply available patches or updates to No-CMS to remediate CVE-2018-25431.
*   Deploy the Sigma rule "Detect CVE-2018-25431 Exploitation Attempt - No-CMS SQL Injection via order_by Parameter" to your SIEM to identify malicious POST requests.
*   Implement input validation and sanitization measures to prevent SQL injection attacks in the `order_by` parameter.
*   Monitor web server logs for suspicious POST requests to `/nocms/main/manage_privilege/index/export` containing SQL syntax in the `order_by[0]` parameter (see Sigma rule and logsource).
*   Review and restrict database user privileges to minimize the impact of successful SQL injection attacks.
