---
title: liyupi yu-picture SQL Injection Vulnerability (CVE-2026-7060)
slug: 2024-01-09-yu-picture-sqli
description: A SQL injection vulnerability (CVE-2026-7060) exists in liyupi yu-picture versions up to a053632c41340152bf75b66b3c543d129123d8ec, allowing a remote attacker to execute arbitrary SQL commands by manipulating the sortField argument in the PageRequest function of PictureServiceImpl.java.
date: "2024-01-09T12:00:00Z"
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7060
  - web-application
vendors:
  - liyupi
products:
  - yu-picture
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7060
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7060
rules:
  - title: Detect Malicious SortField SQL Injection
    description: Detects potential SQL injection attempts in the sortField parameter of web requests based on common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MyBatis-Plus SQL Injection via sortField
    description: Detects SQL injection attempts specifically targeting the sortField parameter used in MyBatis-Plus applications.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in liyupi yu-picture, a web application, affecting versions up to commit a053632c41340152bf75b66b3c543d129123d8ec. The vulnerability, tracked as CVE-2026-7060, resides in the PageRequest function within the PictureServiceImpl.java file, specifically related to the MyBatis-Plus component. An attacker can exploit this vulnerability remotely by manipulating the `sortField` argument. Public exploitation details are available, increasing the risk…
