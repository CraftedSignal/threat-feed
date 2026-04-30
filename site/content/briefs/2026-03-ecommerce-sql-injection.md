---
title: SourceCodester E-Commerce Site SQL Injection Vulnerability (CVE-2026-4613)
slug: 2026-03-ecommerce-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-4613) exists in SourceCodester E-Commerce Site 1.0 within the /products.php file due to improper input sanitization of the 'Search' argument, potentially allowing attackers to read or modify sensitive database information.
date: "2026-03-24T00:16:31Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - ecommerce
  - cve-2026-4613
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4613
  - https://github.com/WHOAMI-xiaoyu/CVE/blob/main/CVE_4.md
  - https://vuldb.com/?id.352477
rules:
  - title: Detecting SQL Injection Attempts in E-Commerce Search
    description: Detects potential SQL injection attempts targeting the /products.php search functionality by looking for common SQL injection characters and keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting Potential SQL Injection in Web Application Logs
    description: This rule identifies potential SQL injection attempts based on the presence of SQL keywords in web application logs.
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

A SQL injection vulnerability, identified as CVE-2026-4613, has been discovered in SourceCodester E-Commerce Site version 1.0. The vulnerability resides within the `/products.php` file and stems from the improper handling of user-supplied input to the 'Search' argument. This allows a remote attacker to inject arbitrary SQL commands, potentially leading to unauthorized access to sensitive data or modification of the database. Given the public availability of exploit code, exploitation of this…
