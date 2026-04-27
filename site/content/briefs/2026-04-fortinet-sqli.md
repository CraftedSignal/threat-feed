---
title: Fortinet FortiDDoS-F SQL Injection Vulnerability (CVE-2026-39815)
slug: 2026-04-fortinet-sqli
description: An SQL injection vulnerability (CVE-2026-39815) in Fortinet FortiDDoS-F versions 7.2.1 through 7.2.2 may allow a low-privilege attacker to execute unauthorized code or commands.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - sqli
  - fortinet
  - cve-2026-39815
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-39815
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39815
  - https://fortiguard.fortinet.com/psirt/FG-IR-26-119
rules:
  - title: Detect Suspicious FortiDDoS-F SQL Injection Attempts
    description: Detects potential SQL injection attempts against Fortinet FortiDDoS-F web interfaces by looking for common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect FortiDDoS-F Unauthorized Access Attempt
    description: Detects attempted access to sensitive FortiDDoS-F web pages without prior authentication.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-39815 is an SQL injection vulnerability affecting Fortinet FortiDDoS-F versions 7.2.1 and 7.2.2. The vulnerability stems from improper neutralization of special elements used in SQL commands. According to Fortinet, an attacker with low privileges could exploit this vulnerability to execute unauthorized code or commands. While the exact attack vector is not detailed in the provided source material, successful exploitation would allow for arbitrary code execution within the context of…
