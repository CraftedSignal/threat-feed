---
title: CMSsite 1.0 SQL Injection Vulnerability (CVE-2019-25697)
slug: 2026-04-cmssite-sqli
description: CMSsite 1.0 is vulnerable to unauthenticated SQL injection (CVE-2019-25697) via the cat_id parameter in category.php, allowing attackers to extract sensitive database information.
date: "2026-04-12T13:16:32Z"
severities:
  - high
tags:
  - sqli
  - cve-2019-25697
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1211
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2019-25697
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25697
  - https://github.com/VictorAlagwu/CMSsite/archive/master.zip
  - https://www.exploit-db.com/exploits/46259
  - https://www.vulncheck.com/advisories/cmssite-sql-injection-via-category-php
rules:
  - title: Detect Suspicious GET Requests to category.php with SQL Injection Attempts
    description: Detects GET requests to category.php with potential SQL injection attempts based on common SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
  - title: Detect SQL error messages in web server logs
    description: Detects SQL error messages in web server logs indicating potential SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CMSsite 1.0 is susceptible to an SQL injection vulnerability (CVE-2019-25697) within the category.php script. This flaw allows unauthenticated, remote attackers to inject arbitrary SQL commands by manipulating the `cat_id` GET parameter. Successful exploitation could lead to the disclosure of sensitive information stored within the database, including user credentials and other application data. Given the ease of exploitation and the potential impact, this vulnerability poses a significant risk…
