---
title: itsourcecode Construction Management System SQL Injection Vulnerability
slug: 2026-04-construction-management-sql-injection
description: A SQL injection vulnerability exists in itsourcecode Construction Management System version 1.0, affecting the processing of the /locations.php file, allowing a remote attacker to inject SQL commands by manipulating the 'address' argument, with a publicly available exploit.
date: "2026-04-27T02:16:01Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-7075
vendors:
  - itsourcecode
products:
  - Construction Management System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7075
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7075
  - https://github.com/Beatriz-ai-boop/cve/issues/4
  - https://itsourcecode.com/
  - https://vuldb.com/submit/799545
  - https://vuldb.com/vuln/359650
  - https://vuldb.com/vuln/359650/cti
rules:
  - title: Detect SQL Injection Attempt in Construction Management System
    description: Detects potential SQL injection attempts targeting the /locations.php endpoint by identifying suspicious SQL syntax within the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via Address Parameter
    description: Detects potential SQL injection attempts by monitoring the address parameter for common SQL injection payloads.
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

A SQL injection vulnerability has been identified in itsourcecode Construction Management System version 1.0. The vulnerability resides within the `/locations.php` file and is triggered by manipulating the `address` argument. This allows a remote attacker to inject arbitrary SQL commands into the application's database queries. This poses a significant risk as successful exploitation could lead to unauthorized data access, modification, or deletion, potentially compromising the entire system…
