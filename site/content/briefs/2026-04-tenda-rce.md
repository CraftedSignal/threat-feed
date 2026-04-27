---
title: Tenda F451 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-rce
description: A stack-based buffer overflow vulnerability in the Tenda F451 router (version 1.0.0.7) allows remote attackers to execute arbitrary code by manipulating the 'page' argument in the fromRouteStatic function of the /goform/RouteStatic file.
date: "2026-04-10T00:16:36Z"
severities:
  - critical
exploited: true
tags:
  - tenda
  - router
  - buffer_overflow
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5989
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5989
  - https://github.com/Jimi-Lab/cve/issues/5
  - https://vuldb.com/vuln/356543
rules:
  - title: Detect Tenda F451 Exploit Attempt
    description: Detects potential exploit attempts against the Tenda F451 router by monitoring requests to the /goform/RouteStatic endpoint with unusually long 'page' arguments, which may indicate a buffer overflow attack.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect High HTTP Status Codes After RouteStatic Access
    description: Detects potential exploit attempts by identifying elevated HTTP status codes after accessing the vulnerable RouteStatic endpoint.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-5989, affects the Tenda F451 router, specifically version 1.0.0.7. The vulnerability lies within the `fromRouteStatic` function of the `/goform/RouteStatic` file. By manipulating the `page` argument, a remote attacker can trigger a stack-based buffer overflow, potentially leading to arbitrary code execution. Publicly available exploit code exists, increasing the risk of exploitation. This vulnerability poses a significant threat as it allows…
