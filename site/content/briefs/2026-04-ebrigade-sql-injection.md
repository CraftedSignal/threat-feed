---
title: eBrigade ERP 4.5 SQL Injection Vulnerability (CVE-2019-25707)
slug: 2026-04-ebrigade-sql-injection
description: eBrigade ERP 4.5 is vulnerable to SQL injection via the 'id' parameter in pdf.php, allowing authenticated attackers to execute arbitrary SQL queries and extract sensitive database information.
date: "2026-04-12T13:16:33Z"
severities:
  - high
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
ioc_counts:
  email: 1
  url: 4
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

eBrigade ERP 4.5 is susceptible to an SQL injection vulnerability (CVE-2019-25707) that enables authenticated attackers to execute arbitrary SQL queries. The vulnerability is located in the pdf.php script and is triggered via the 'id' parameter. By injecting malicious SQL code into this parameter through a GET request, an attacker can potentially extract sensitive information from the database, including table names and schema details. This vulnerability poses a significant risk to…
