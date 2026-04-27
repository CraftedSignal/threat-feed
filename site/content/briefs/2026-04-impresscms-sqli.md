---
title: ImpressCMS 1.3.11 Time-Based Blind SQL Injection Vulnerability
slug: 2026-04-impresscms-sqli
description: ImpressCMS 1.3.11 contains a time-based blind SQL injection vulnerability allowing authenticated attackers to manipulate database queries by injecting SQL code through the 'bid' parameter via POST requests to the admin.php endpoint.
date: "2026-04-12T13:16:33Z"
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

ImpressCMS is an open-source content management system. Version 1.3.11 is vulnerable to a time-based blind SQL injection vulnerability (CVE-2019-25703). An authenticated attacker can exploit this vulnerability by injecting malicious SQL code into the 'bid' parameter. Successful exploitation allows the attacker to manipulate database queries, potentially leading to the extraction of sensitive information. This vulnerability requires authentication, limiting the scope of potential attackers, but…
