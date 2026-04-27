---
title: Simple Laundry System SQL Injection Vulnerability (CVE-2026-5648)
slug: 2026-04-simple-laundry-sql-injection
description: A remote SQL injection vulnerability exists in code-projects Simple Laundry System 1.0 due to improper input validation in the firstName parameter of /userfinishregister.php, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-04-06T11:17:03Z"
severities:
  - high
tags:
  - cve-2026-5648
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5648
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5648
  - https://code-projects.org/
  - https://github.com/yao536/cve/issues/2
  - https://vuldb.com/submit/786194
  - https://vuldb.com/vuln/355436
  - https://vuldb.com/vuln/355436/cti
rules:
  - title: Detect Suspicious URI Access to userfinishregister.php
    description: Detects access to the vulnerable userfinishregister.php page, which may indicate exploitation attempts
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in URI
    description: Detects potential SQL injection attempts based on suspicious characters in the URI
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-5648, affects the code-projects Simple Laundry System version 1.0. The vulnerability resides within the `/userfinishregister.php` file, specifically in the Parameter Handler component. By manipulating the `firstName` argument, a remote attacker can inject arbitrary SQL commands. The vulnerability allows unauthenticated remote exploitation, and a proof-of-concept exploit has been published, increasing the risk of widespread exploitation. This…
