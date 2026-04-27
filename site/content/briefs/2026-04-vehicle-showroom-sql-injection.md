---
title: Vehicle Showroom Management System SQL Injection Vulnerability (CVE-2026-6038)
slug: 2026-04-vehicle-showroom-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-6038) exists in the code-projects Vehicle Showroom Management System 1.0, specifically affecting the /util/RegisterCustomerFunction.php file by manipulating the BRANCH_ID argument.
date: "2026-04-10T09:20:18Z"
severities:
  - high
tags:
  - cve-2026-6038
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6038
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6038
  - https://vuldb.com/vuln/356619
rules:
  - title: Detect SQL Injection Attempt via BRANCH_ID Parameter
    description: Detects potential SQL injection attempts targeting the BRANCH_ID parameter in the /util/RegisterCustomerFunction.php file.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Direct Access to RegisterCustomerFunction.php
    description: Detects direct access attempts to the RegisterCustomerFunction.php file, which may indicate reconnaissance or exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-6038, has been discovered in version 1.0 of the code-projects Vehicle Showroom Management System. This vulnerability resides within the `/util/RegisterCustomerFunction.php` file, and can be exploited by manipulating the `BRANCH_ID` argument. The vulnerability allows for remote exploitation, meaning an attacker does not need local access to the system. Publicly available exploit code exists, increasing the likelihood of exploitation…
