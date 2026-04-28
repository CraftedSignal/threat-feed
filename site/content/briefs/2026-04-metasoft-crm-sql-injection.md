---
title: Metasoft MetaCRM SQL Injection Vulnerability (CVE-2026-6629)
slug: 2026-04-metasoft-crm-sql-injection
description: A SQL injection vulnerability (CVE-2026-6629) exists in Metasoft MetaCRM up to version 6.4.0, allowing remote attackers to execute arbitrary SQL commands via manipulation of the sql argument in the Statement.executeUpdate function of the sql.jsp file.
date: "2026-04-20T11:16:18Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-6629
  - sql-injection
  - web-application
  - metasoft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6629
  - https://my.feishu.cn/docx/JttndUaPLoR88HxI1alcz1uencf?from=from_copylink
  - https://vuldb.com/submit/792615
  - https://vuldb.com/vuln/358263
  - https://vuldb.com/vuln/358263/cti
rules:
  - title: Detect Metasoft MetaCRM SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the sql.jsp file in Metasoft MetaCRM by looking for suspicious SQL syntax in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Metasoft MetaCRM SQL Error
    description: Detects SQL errors returned by the server, which could indicate a successful SQL injection.
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

A SQL injection vulnerability, identified as CVE-2026-6629, has been discovered in Metasoft 美特软件 MetaCRM versions up to 6.4.0. The vulnerability resides within the `sql.jsp` file, specifically affecting the `Statement.executeUpdate` function of the Interface component. The vulnerability allows remote attackers to inject arbitrary SQL commands by manipulating the `sql` argument. Public exploit code is available, increasing the risk of exploitation. The vendor was notified but did not respond. This vulnerability poses a significant threat to organizations using the affected MetaCRM versions, potentially leading to data breaches, system compromise, and unauthorized access.

## Attack Chain

1.  An attacker identifies a Metasoft MetaCRM instance running a vulnerable version (<= 6.4.0).
2.  The attacker crafts a malicious HTTP request targeting the `sql.jsp` file.
3.  Within the HTTP request, the attacker manipulates the `sql` parameter to inject SQL code.
4.  The crafted SQL injection payload is passed to the `Statement.executeUpdate` function.
5.  The application executes the attacker-controlled SQL query against the underlying database.
6.  The database server executes the malicious SQL command.
7.  The attacker can read sensitive data from the database, modify existing data, or execute administrative commands.
8.  The attacker gains unauthorized access to the system, potentially leading to complete system compromise or data exfiltration.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to a range of severe consequences, including unauthorized data access, data modification, and complete system compromise. Attackers could steal sensitive customer data, financial records, or intellectual property. They might also be able to modify existing data to cause financial losses or disrupt business operations. The lack of vendor response exacerbates the risk, as no official patch or mitigation is available. The CVSS score of 7.3 reflects the high potential impact of this vulnerability.

## Recommendation

*   Inspect web server logs for suspicious POST requests targeting `sql.jsp` with potentially malicious SQL queries in the `sql` parameter to detect exploitation attempts. Reference the Sigma rule `Detect-Metasoft-MetaCRM-SQL-Injection`.
*   Deploy the Sigma rule `Detect-Metasoft-MetaCRM-SQL-Error` to detect SQL errors that may indicate injection attempts.
*   Apply input validation and sanitization to the `sql` parameter in `sql.jsp` to prevent SQL injection. This requires modifying the application code.
*   Monitor network traffic for unusual database activity originating from the web server, such as large data transfers or unauthorized access attempts.
