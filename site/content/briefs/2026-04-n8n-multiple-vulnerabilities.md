---
title: Multiple Vulnerabilities in n8n Workflow Automation Tool
slug: 2026-04-n8n-multiple-vulnerabilities
description: Multiple vulnerabilities in n8n can be exploited by an attacker to execute arbitrary code, bypass security measures, disclose sensitive information, conduct SQL injection attacks, cause denial-of-service, perform cross-site scripting, redirect users, or hijack sessions.
date: "2026-04-23T10:23:56Z"
severities:
  - critical
tags:
  - n8n
  - vulnerability
  - sqli
  - xss
  - rce
  - session-hijacking
vendors:
  - n8n
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: Indicator Removal on Host
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: OS Credential Dumping
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Application Layer Protocol
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1251
rules:
  - title: Detect Suspicious n8n Process Creation with Network Connection
    description: Detects unusual processes spawned by n8n that also initiate network connections, which may indicate exploitation or malicious workflow execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential SQL Injection Attempts in n8n Logs
    description: 'Detects potential SQL injection attempts by looking for specific SQL keywords within n8n webserver logs. Note: Requires specific n8n webserver logging configuration.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect n8n Workflow Modification by Suspicious Process
    description: Detects modifications to n8n workflow files by processes other than n8n itself, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Multiple vulnerabilities have been identified in n8n, a workflow automation tool. An attacker exploiting these vulnerabilities could achieve a range of malicious outcomes, including remote code execution, security bypass, information disclosure, SQL injection, denial-of-service, cross-site scripting (XSS), malicious redirection, and session hijacking. The vulnerabilities stem from insufficient input validation, insecure configurations, or design flaws within the n8n application. Successful…
