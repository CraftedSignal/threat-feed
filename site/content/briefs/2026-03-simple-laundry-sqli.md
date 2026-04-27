---
title: SQL Injection Vulnerability in Simple Laundry System 1.0
slug: 2026-03-simple-laundry-sqli
description: CVE-2026-4579 is a SQL injection vulnerability in code-projects Simple Laundry System 1.0, affecting the /viewdetail.php file and allowing remote attackers to manipulate the serviceId argument.
date: "2026-03-23T08:16:18Z"
severities:
  - high
tags:
  - sqli
  - vulnerability
  - webapp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4579
  - https://vuldb.com/?id.352416
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect SQL Injection in Simple Laundry System
    description: Detects potential SQL injection attempts targeting the /viewdetail.php endpoint in Simple Laundry System by monitoring for suspicious characters and SQL keywords in the serviceId parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Payloads in HTTP Requests
    description: This rule detects common SQL injection payloads within HTTP request parameters.
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

A SQL injection vulnerability, CVE-2026-4579, has been identified in code-projects Simple Laundry System version 1.0. The vulnerability resides within the Parameters Handler component, specifically in the /viewdetail.php file. By manipulating the 'serviceId' argument, a remote attacker can inject arbitrary SQL commands. The vulnerability allows for remote exploitation, and a public exploit is available, increasing the likelihood of exploitation. This vulnerability poses a significant threat to…
