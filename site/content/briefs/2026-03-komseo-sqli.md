---
title: KomSeo Cart 1.3 SQL Injection Vulnerability
slug: 2026-03-komseo-sqli
description: KomSeo Cart 1.3 is vulnerable to SQL injection via the 'my_item_search' parameter in edit.php, allowing attackers to inject SQL commands and extract sensitive database information.
date: "2026-03-26T12:16:05Z"
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25206
  - https://sitemakin.com
  - https://www.exploit-db.com/exploits/44753
  - https://www.vulncheck.com/advisories/komseo-cart-sql-injection-via-edit-php
rules:
  - title: Detect KomSeo Cart SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the 'my_item_search' parameter in KomSeo Cart's edit.php file.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects common SQL error messages in web server responses, indicating potential SQL injection attempts.
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

KomSeo Cart version 1.3 is susceptible to SQL injection attacks through the 'my_item_search' parameter found within the edit.php file. This vulnerability allows unauthenticated attackers to inject arbitrary SQL commands into the application's database queries. Successful exploitation of this flaw enables attackers to extract sensitive information from the database, potentially compromising user credentials, financial data, or other confidential information. The vulnerability can be exploited…
