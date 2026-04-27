---
title: Simple Content Management System 1.0 SQL Injection Vulnerability
slug: 2026-04-simple-cms-sqli
description: A remote SQL injection vulnerability exists in code-projects Simple Content Management System 1.0 due to improper handling of the ID argument in the /web/index.php file, allowing unauthenticated attackers to execute arbitrary SQL queries.
date: "2026-04-14T12:00:00Z"
severities:
  - high
tags:
  - sqli
  - cve-2026-6183
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6183
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6183
  - https://code-projects.org/
  - https://github.com/Xmyronn/simple-cms-sqli-id-parameter
  - https://vuldb.com/submit/797264
  - https://vuldb.com/vuln/357106
  - https://vuldb.com/vuln/357106/cti
ioc_counts:
  url: 5
rules:
  - title: Detect Simple CMS SQL Injection Attempt
    description: Detects potential SQL injection attempts against Simple CMS by looking for SQL keywords in the ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connection After Simple CMS Exploit
    description: Detects suspicious outbound connections from the web server after a potential Simple CMS exploit.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in code-projects Simple Content Management System version 1.0. The vulnerability resides in the `/web/index.php` file and can be exploited by manipulating the `ID` argument. An attacker can remotely inject malicious SQL queries, potentially leading to unauthorized data access, modification, or deletion. Public exploits are available, increasing the risk of exploitation. The affected software is a content management system, typically used for…
