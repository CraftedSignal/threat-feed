---
title: Inout Article Base CMS SQL Injection Vulnerability (CVE-2019-25640)
slug: 2026-03-inout-article-sql-injection
description: Inout Article Base CMS is vulnerable to SQL injection, allowing unauthenticated attackers to manipulate database queries through the 'p' and 'u' parameters via XOR-based payloads in GET requests to portalLogin.php, potentially leading to sensitive information extraction or denial-of-service.
date: "2026-03-24T12:16:05Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - cve-2019-25640
  - inout-article-base-cms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25640
  - https://www.exploit-db.com/exploits/46593
  - https://www.inoutscripts.com/products/inout-article-base/
  - https://www.vulncheck.com/advisories/inout-article-base-cms-lastest-sql-injection-via-portallogin-php
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Inout Article Base CMS portalLogin.php SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting portalLogin.php in Inout Article Base CMS by identifying XOR-based SQL injection patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Inout Article Base CMS portalLogin.php Access
    description: Detects access to the portalLogin.php page which may indicate exploitation attempts
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Inout Article Base CMS is susceptible to SQL injection vulnerabilities (CVE-2019-25640). Unauthenticated attackers can exploit these vulnerabilities by manipulating database queries via the 'p' and 'u' parameters in GET requests to the `portalLogin.php` script. The attack leverages XOR-based SQL injection payloads. Successful exploitation can allow attackers to extract sensitive database information or cause a denial of service through time-based attacks. This vulnerability poses a significant…
