---
title: Multiple Vulnerabilities in Fortinet FortiSandbox
slug: 2026-04-fortinet-fortisandbox-vulns
description: Multiple vulnerabilities in Fortinet FortiSandbox allow attackers to perform cross-site scripting attacks, disclose information, bypass security measures, and execute arbitrary code, potentially leading to system compromise.
date: "2026-04-21T10:00:00Z"
severities:
  - high
tags:
  - fortinet
  - fortisandbox
  - vulnerability
  - xss
  - code-execution
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1094
rules:
  - title: Detect Suspicious FortiSandbox HTTP Requests
    description: Detects suspicious HTTP requests to FortiSandbox that may indicate exploitation attempts, such as directory traversal or command injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect FortiSandbox Configuration File Access
    description: Detects attempts to access sensitive configuration files on FortiSandbox, potentially indicating information disclosure attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - linux
  - title: Detect Potential Code Execution via Web Shell on FortiSandbox
    description: Detects creation of common web shell file extensions within the FortiSandbox web root, suggesting potential remote code execution.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Fortinet FortiSandbox is susceptible to multiple vulnerabilities that could allow a malicious actor to compromise the system. While the specific CVEs and affected versions are not detailed in the source, the vulnerabilities enable a range of attacks including Cross-Site Scripting (XSS), information disclosure, security bypass, and ultimately, arbitrary code execution. Successful exploitation could allow attackers to gain unauthorized access, steal sensitive data, or disrupt services. Defenders…
