---
title: SQL Injection Vulnerability in Lost and Found Thing Management 1.0
slug: 2026-04-lost-found-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-6163) exists in code-projects Lost and Found Thing Management 1.0 via manipulation of the 'cat' parameter in /catageory.php, potentially allowing attackers to read, modify, or delete database information.
date: "2026-04-13T06:16:06Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6163
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6163
  - https://code-projects.org/
  - https://github.com/lanPwa/CVE/issues/2
  - https://vuldb.com/submit/797088
  - https://vuldb.com/vuln/357051
  - https://vuldb.com/vuln/357051/cti
rules:
  - title: Detect Suspicious SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts targeting the /catageory.php endpoint by looking for common SQL keywords in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt via POST Request
    description: Detects potential SQL injection attacks via POST requests by identifying SQL keywords in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical SQL injection vulnerability has been identified in code-projects Lost and Found Thing Management version 1.0, tracked as CVE-2026-6163. This vulnerability resides within the `/catageory.php` file and can be exploited by remotely manipulating the `cat` parameter. Due to the application's failure to properly sanitize user-supplied input, an attacker can inject arbitrary SQL code, potentially leading to unauthorized data access, modification, or deletion. The existence of a publicly…
