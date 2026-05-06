---
title: eBrigade ERP 4.5 SQL Injection Vulnerability (CVE-2019-25707)
slug: 2026-04-ebrigade-sql-injection
description: eBrigade ERP 4.5 is vulnerable to SQL injection via the 'id' parameter in pdf.php, allowing authenticated attackers to execute arbitrary SQL queries and extract sensitive database information.
date: "2026-04-12T13:16:33Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - cve-2019-25707
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25707
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25707
  - https://ebrigade.net/
  - https://netcologne.dl.sourceforge.net/project/ebrigade/ebrigade/eBrigade%204.5/ebrigade_4.5.zip
  - https://www.exploit-db.com/exploits/46117
  - https://www.vulncheck.com/advisories/ebrigade-erp-sql-injection-via-pdf-php
iocs:
  - type: url
    value: https://ebrigade.net/
  - type: url
    value: https://netcologne.dl.sourceforge.net/project/ebrigade/ebrigade/eBrigade%204.5/ebrigade_4.5.zip
ioc_counts:
  url: 2
rules:
  - title: Detect SQL Injection Attempts in eBrigade ERP pdf.php
    description: Detects potential SQL injection attempts targeting the pdf.php endpoint in eBrigade ERP 4.5 by identifying suspicious SQL syntax within the 'id' parameter of GET requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Error Responses After SQL Injection Attempt in eBrigade ERP pdf.php
    description: Detects potential SQL injection attempts targeting the pdf.php endpoint in eBrigade ERP 4.5 by identifying 500 errors after a request with SQL syntax.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

eBrigade ERP 4.5 is susceptible to an SQL injection vulnerability (CVE-2019-25707) that enables authenticated attackers to execute arbitrary SQL queries. The vulnerability is located in the pdf.php script and is triggered via the 'id' parameter. By injecting malicious SQL code into this parameter through a GET request, an attacker can potentially extract sensitive information from the database, including table names and schema details. This vulnerability poses a significant risk to organizations using eBrigade ERP 4.5, as successful exploitation could lead to data breaches, compromised credentials, and other malicious activities. The vulnerability was published on 2026-04-12.

## Attack Chain

1. An attacker gains valid credentials for eBrigade ERP 4.5 either through credential stuffing or some other credential compromise technique.
2. The attacker crafts a malicious SQL payload designed to extract sensitive information or manipulate the database.
3. The attacker constructs a GET request targeting the pdf.php endpoint, embedding the malicious SQL payload within the 'id' parameter (e.g., `pdf.php?id=1' UNION SELECT ...`).
4. The server-side application fails to properly sanitize or validate the 'id' parameter before incorporating it into an SQL query.
5. The application executes the attacker-controlled SQL query against the database.
6. The database returns the results of the injected SQL query to the application.
7. The application displays the extracted data to the attacker.
8. The attacker uses the extracted data (database schema, usernames, passwords, etc.) to further compromise the application or gain unauthorized access to other systems.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2019-25707) can lead to the extraction of sensitive information from the eBrigade ERP 4.5 database. This could include customer data, financial records, employee information, and other confidential data. The impact could range from data breaches and financial losses to reputational damage and legal repercussions. While the exact number of victims is unknown, any organization using eBrigade ERP 4.5 is potentially at risk.

## Recommendation

*   Inspect web server access logs for suspicious GET requests to `pdf.php` containing SQL syntax in the `id` parameter to detect exploitation attempts using the provided Sigma rule.
*   Apply input validation and sanitization to the 'id' parameter in `pdf.php` to prevent SQL injection attacks.
*   Upgrade to a patched version of eBrigade ERP or apply the necessary security patches provided by the vendor to remediate CVE-2019-25707.
*   Monitor network traffic for unusual database activity originating from the eBrigade ERP 4.5 server.
*   Block access to the known exploit URL (`https://www.exploit-db.com/exploits/46117`) at your web proxy or firewall.
