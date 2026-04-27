---
title: CrewAI Vulnerabilities Allow Remote Code Execution
slug: 2026-04-crewai-rce
description: Multiple vulnerabilities in CrewAI, an open-source multi-agent orchestration framework, can be exploited by attackers through prompt injection to execute arbitrary code and perform other malicious activities, potentially leading to system compromise.
date: "2026-04-01T12:00:00Z"
severities:
  - critical
tags:
  - ai
  - rce
  - prompt-injection
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-2275
  - id: CVE-2026-2286
  - id: CVE-2026-2287
  - id: CVE-2026-2285
references:
  - https://www.securityweek.com/crewai-vulnerabilities-expose-devices-to-hacking/
rules:
  - title: Detect CrewAI Sandbox Escape via Arbitrary File Read
    description: Detects attempts to read arbitrary files on the server via the CrewAI JSON loader tool vulnerability (CVE-2026-2285), indicating a potential sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect CrewAI SSRF Attempts
    description: Detects potential Server-Side Request Forgery (SSRF) attempts related to CVE-2026-2286 by monitoring network connections initiated by CrewAI processes to internal or cloud services.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect SandboxPython Fallback
    description: Detects the fallback to SandboxPython due to Docker inaccessibility, which may indicate CVE-2026-2275 exploitation
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

CrewAI, an open-source multi-agent orchestration framework based on Python, is vulnerable to a chain of exploits that can lead to remote code execution. Discovered by Yarden Porat of Cyata, these vulnerabilities (CVE-2026-2275, CVE-2026-2286, CVE-2026-2287, CVE-2026-2285) are linked to the Code Interpreter tool, which allows users to execute Python code within a Docker container. Attackers can leverage prompt injection to exploit these bugs, escaping the sandbox environment and executing…
