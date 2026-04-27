---
title: OpenDocMan 1.3.4 SQL Injection Vulnerability
slug: 2026-04-opendocman-sqli
description: OpenDocMan version 1.3.4 is vulnerable to SQL injection, allowing unauthenticated attackers to manipulate database queries via the 'where' parameter in search.php to extract sensitive information.
date: "2026-04-05T21:16:46Z"
severities:
  - high
tags:
  - sqli
  - vulnerability
  - opendocman
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25684
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25684
  - https://sourceforge.net/projects/opendocman/files/
  - https://www.exploit-db.com/exploits/46500
  - https://www.vulncheck.com/advisories/opendocman-sql-injection-via-where-parameter
rules:
  - title: Detect SQL Injection Attempt in OpenDocMan search.php
    description: Detects potential SQL injection attempts by looking for specific SQL keywords in the 'where' parameter of requests to search.php in OpenDocMan.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenDocMan SQL Injection via GET Request to search.php
    description: This rule detects GET requests to search.php with a 'where' parameter that contains SQL keywords indicative of an injection attempt.
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

OpenDocMan 1.3.4 is susceptible to SQL injection attacks due to insufficient input validation. An unauthenticated attacker can inject malicious SQL code into the 'where' parameter of the `search.php` endpoint. This vulnerability allows attackers to bypass normal query restrictions, potentially leading to the extraction of sensitive data from the database. The vulnerability was published on 2026-04-05 and assigned CVE-2019-25684. Successful exploitation grants attackers unauthorized access to…
