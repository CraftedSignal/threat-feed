---
title: Simopro WinMatrix Agent Missing Authentication Vulnerability (CVE-2026-6348)
slug: 2026-04-winmatrix-missing-auth
description: The WinMatrix agent by Simopro Technology suffers from a missing authentication vulnerability (CVE-2026-6348), enabling local authenticated attackers to execute arbitrary code with SYSTEM privileges on the local machine and all hosts within the agent's environment.
date: "2026-04-16T03:16:30Z"
severities:
  - critical
tags:
  - CVE-2026-6348
  - missing-authentication
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6348
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6348
  - https://www.twcert.org.tw/en/cp-139-10840-ba9b9-2.html
  - https://www.twcert.org.tw/tw/cp-132-10839-2d9a7-1.html
rules:
  - title: Detect WinMatrix Agent Suspicious Child Processes
    description: Detects suspicious child processes spawned by the WinMatrix agent process, potentially indicating exploitation of CVE-2026-6348.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect WinMatrix Agent Network Connections
    description: Detects unusual network connections initiated by the WinMatrix agent process.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The WinMatrix agent, developed by Simopro Technology, contains a critical missing authentication vulnerability, identified as CVE-2026-6348. This flaw allows an attacker with local authenticated access to execute arbitrary code with SYSTEM privileges. The scope of impact extends beyond the compromised host, potentially affecting all machines within the WinMatrix agent's managed environment. Exploitation of this vulnerability would allow an attacker to gain full control over affected systems…
