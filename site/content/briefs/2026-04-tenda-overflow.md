---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability (CVE-2026-6121)
slug: 2026-04-tenda-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-6121) exists in the WrlclientSet function of the /goform/WrlclientSet file in the httpd component of Tenda F451 version 1.0.0.7, allowing remote attackers to execute arbitrary code by manipulating the GO argument.
date: "2026-04-12T08:16:36Z"
severities:
  - critical
tags:
  - cve-2026-6121
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6121
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6121
  - https://github.com/Jimi-Lab/cve/issues/12
  - https://vuldb.com/vuln/356984
rules:
  - title: Detect Suspiciously Long GO Parameter in Tenda WrlclientSet Request
    description: Detects HTTP POST requests to the /goform/WrlclientSet endpoint with an unusually long GO parameter, indicative of a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP POST to /goform/WrlclientSet
    description: Detects HTTP POST requests to the /goform/WrlclientSet endpoint.
    platform: sigma
    severity: low
    tactics:
      - exploitation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6121 is a stack-based buffer overflow vulnerability affecting Tenda F451 router version 1.0.0.7. The vulnerability resides within the `WrlclientSet` function located in the `/goform/WrlclientSet` file of the `httpd` component. An attacker can exploit this vulnerability by sending a specially crafted HTTP request to the affected router, specifically manipulating the `GO` argument. Due to insufficient bounds checking on the `GO` argument's size when passed to the `WrlclientSet` function…
