---
title: IBM Verify Access and Security Verify Access Container Privilege Escalation (CVE-2026-1346)
slug: 2026-04-ibm-privesc
description: A locally authenticated user can escalate privileges to root on vulnerable IBM Verify Identity Access Container and IBM Security Verify Access Container installations due to the execution of processes with unnecessary privileges, as tracked by CVE-2026-1346.
date: "2026-04-08T01:16:40Z"
severities:
  - critical
tags:
  - privilege-escalation
  - cve-2026-1346
  - ibm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-1346
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1346
  - https://www.ibm.com/support/pages/node/7268253
rules:
  - title: Suspicious Process Execution from IBM Verify Access Container
    description: Detects suspicious processes spawned by IBM Verify Access Container binaries, potentially indicating privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: IBM Verify Access Container - Unauthorized File Modification
    description: Detects unauthorized file modifications by IBM Verify Access Container that could lead to privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

IBM Verify Identity Access Container versions 11.0 through 11.0.2, IBM Security Verify Access Container versions 10.0 through 10.0.9.1, IBM Verify Identity Access versions 11.0 through 11.0.2, and IBM Security Verify Access versions 10.0 through 10.0.9.1 are susceptible to a privilege escalation vulnerability. This flaw, identified as CVE-2026-1346, allows a locally authenticated user to gain root privileges. The vulnerability stems from the execution of certain processes with unnecessary…
