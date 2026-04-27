---
title: Apache ActiveMQ Classic RCE via Jolokia API Exploitation
slug: 2026-04-activemq-rce
description: A remote code execution vulnerability (CVE-2026-34197) in Apache ActiveMQ Classic allows authenticated attackers to invoke management operations through the Jolokia API to retrieve a remote configuration file and execute OS commands, potentially exploitable without authentication via CVE-2024-32114.
date: "2026-04-08T14:30:27Z"
severities:
  - critical
tags:
  - activemq
  - rce
  - jolokia
  - cve-2026-34197
  - cve-2024-32114
  - cve-2022-41678
  - spring-xml
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-34197
    cvss: 8.8
    epss: 0.65266
  - id: CVE-2024-32114
    cvss: 8.5
    epss: 0.02024
  - id: CVE-2022-41678
    cvss: 8.8
    epss: 0.93623
references:
  - https://www.securityweek.com/rce-bug-lurked-in-apache-activemq-classic-for-13-years/
rules:
  - title: ActiveMQ Jolokia API Access
    description: Detects access to the Jolokia API endpoint in Apache ActiveMQ.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: ActiveMQ Suspicious Process Creation
    description: Detects suspicious process creation events originating from the ActiveMQ Java process.
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

A remote code execution vulnerability, CVE-2026-34197, has been identified in Apache ActiveMQ Classic, an open-source messaging and Integration Patterns server widely used across industries. This vulnerability, present for 13 years, allows attackers to invoke management operations through the Jolokia API and instruct the broker to retrieve a remote configuration file, leading to OS command execution. This is achieved by bypassing CVE-2022-41678, a previous bug that allowed webshell creation…
