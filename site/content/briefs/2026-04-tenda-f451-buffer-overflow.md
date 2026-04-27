---
title: Tenda F451 Router Buffer Overflow Vulnerability
slug: 2026-04-tenda-f451-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-6631) in Tenda F451 router version 1.0.0.7_cn_svn7958 allows remote attackers to execute arbitrary code by manipulating the 'page' argument in the /goform/webExcptypemanFilter component.
date: "2026-04-20T11:16:19Z"
severities:
  - critical
tags:
  - tenda
  - router
  - buffer_overflow
  - cve-2026-6631
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6631
  - https://github.com/Jimi-Lab/cve/issues/25
  - https://vuldb.com/vuln/358265
rules:
  - title: Detect Tenda F451 Buffer Overflow Attempt
    description: Detects suspicious requests to /goform/webExcptypemanFilter with unusually long 'page' parameters, indicative of a buffer overflow attempt (CVE-2026-6631).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F451 Suspicious Process
    description: Detects suspicious processes spawned by the httpd daemon on Tenda F451 routers, potentially indicating successful exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-6631 is a critical buffer overflow vulnerability affecting Tenda F451 routers running firmware version 1.0.0.7_cn_svn7958. The vulnerability resides in the `fromwebExcptypemanFilter` function within the `/goform/webExcptypemanFilter` component of the router's `httpd` web server. A remote, unauthenticated attacker can exploit this vulnerability by sending a specially crafted HTTP request with an overly long 'page' parameter. Publicly available exploits exist, increasing the risk of…
