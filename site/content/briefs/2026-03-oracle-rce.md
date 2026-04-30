---
title: Oracle Fusion Middleware RCE Vulnerability (CVE-2026-21992)
slug: 2026-03-oracle-rce
description: CVE-2026-21992 allows an unauthenticated attacker to gain network access via HTTP and execute code remotely on Oracle Identity Manager and Oracle Web Services Manager.
date: "2026-03-24T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - vulnerability
  - rce
  - oracle
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
  - https://www.sophos.com/en-us/blog/oracle-vulnerability-cve-2026-21992-impacts-core-products
rules:
  - title: Detect Suspicious HTTP Request to Oracle Fusion Middleware
    description: Detects suspicious HTTP requests to Oracle Fusion Middleware components that may indicate exploitation attempts of CVE-2026-21992
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Oracle Web Services Manager RCE via HTTP Request
    description: Detects suspicious HTTP requests to Oracle Web Services Manager components that may indicate exploitation attempts of CVE-2026-21992, looking for specific URIs often targeted in web exploits.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 20, 2026, Oracle disclosed CVE-2026-21992, a critical vulnerability (CVSS score of 9.8) affecting Oracle Fusion Middleware, specifically Oracle Identity Manager and Oracle Web Services Manager. The vulnerability stems from a lack of network-level authentication, allowing unauthenticated attackers to exploit exposed critical functions via HTTP. Successful exploitation allows for remote code execution. While there are currently no reports of active exploitation, the potential impact…
