---
title: SQL Injection Vulnerability in Simple Laundry System 1.0
slug: 2026-03-simple-laundry-sqli
description: A remote SQL Injection vulnerability exists in code-projects Simple Laundry System 1.0 within the Parameter Handler component's /checkregisitem.php file, where manipulating the Long-arm-shirtVol argument can trigger the injection, with a publicly available exploit.
date: "2026-03-26T08:16:22Z"
severities:
  - high
tags:
  - sqli
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4850
  - https://code-projects.org/
  - https://github.com/kbloow/CVE/issues/1
  - https://vuldb.com/?ctiid.353155
  - https://vuldb.com/?id.353155
  - https://vuldb.com/?submit.776184
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect Suspicious checkregisitem.php SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the checkregisitem.php endpoint by looking for common SQL keywords in the Long-arm-shirtVol parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL error messages in web server logs
    description: Detects SQL error messages in web server logs, which may indicate a SQL injection vulnerability.
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

A critical security flaw has been identified in code-projects Simple Laundry System version 1.0. This vulnerability, tracked as CVE-2026-4850, resides within the Parameter Handler component, specifically in the `/checkregisitem.php` file. The vulnerability allows for remote SQL injection through the manipulation of the `Long-arm-shirtVol` argument. Successful exploitation could lead to unauthorized database access, data breaches, or complete system compromise. The availability of a public…
