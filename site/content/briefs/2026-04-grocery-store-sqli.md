---
title: SQL Injection Vulnerability in anirudhkannan Grocery Store Management System 1.0 (CVE-2025-63939)
slug: 2026-04-grocery-store-sqli
description: A critical SQL injection vulnerability (CVE-2025-63939) exists in the anirudhkannan Grocery Store Management System 1.0, allowing unauthenticated attackers to execute arbitrary SQL queries via the sitem_name POST parameter in /Grocery/search_products_itname.php.
date: "2026-04-14T16:16:33Z"
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - cve-2025-63939
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-63939
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-63939
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2025-63939
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detecting SQL Injection Attempts via sitem_name Parameter
    description: Detects potential SQL injection attempts targeting the sitem_name parameter in the /Grocery/search_products_itname.php endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting Potential SQL Injection Error Responses
    description: Detects web server responses indicative of SQL injection errors, suggesting potential exploitation attempts.
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

CVE-2025-63939 is a SQL injection vulnerability found in anirudhkannan Grocery Store Management System version 1.0. The vulnerability resides in the `/Grocery/search_products_itname.php` script, specifically related to improper input handling of the `sitem_name` POST parameter. An unauthenticated attacker can exploit this vulnerability by injecting malicious SQL code into the `sitem_name` parameter, potentially leading to unauthorized access to the database, data exfiltration, modification, or…
