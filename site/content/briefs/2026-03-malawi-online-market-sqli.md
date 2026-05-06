---
title: SourceCodester Malawi Online Market SQL Injection Vulnerability (CVE-2026-4838)
slug: 2026-03-malawi-online-market-sqli
description: A remote SQL injection vulnerability (CVE-2026-4838) exists in the /display.php file of SourceCodester Malawi Online Market 1.0 due to improper input sanitization of the ID parameter, potentially allowing attackers to execute arbitrary SQL queries.
date: "2026-03-26T04:17:13Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - web-application
  - cve-2026-4838
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4838
  - https://github.com/WHOAMI-xiaoyu/CVE/blob/main/CVE_8.md
  - https://vuldb.com/?ctiid.353141
  - https://vuldb.com/?id.353141
  - https://vuldb.com/?submit.776081
  - https://www.sourcecodester.com/
rules:
  - title: Detect Suspicious URI Access to display.php with SQL Injection Attempts
    description: Detects potential SQL injection attempts by monitoring URI access to the /display.php endpoint with suspicious SQL-related keywords.
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
  - title: Detect SQL Injection Error Messages
    description: Detects SQL injection attempts by looking for common error messages in web server logs that often occur during failed SQL injection attempts.
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

The SourceCodester Malawi Online Market 1.0 is vulnerable to SQL injection (CVE-2026-4838). The vulnerability resides within the `/display.php` file, specifically in how the application handles the `ID` parameter. A remote attacker can manipulate this parameter to inject arbitrary SQL commands into the database query. This can potentially allow the attacker to read, modify, or delete sensitive data, or even gain control of the underlying database server. The vulnerability was published on…
