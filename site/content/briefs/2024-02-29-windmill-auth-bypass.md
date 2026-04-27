---
title: Windmill Missing Authorization Vulnerability (CVE-2026-22683)
slug: 2024-02-29-windmill-auth-bypass
description: Windmill versions 1.56.0 through 1.614.0 contain a missing authorization vulnerability (CVE-2026-22683) that allows users with the Operator role to bypass intended restrictions and perform unauthorized entity creation and modification actions via the backend API, potentially leading to privilege escalation and remote code execution.
date: "2026-04-07T17:16:27Z"
severities:
  - critical
tags:
  - windmill
  - authorization-bypass
  - privilege-escalation
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-22683
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22683
rules:
  - title: Detect Windmill Unauthorized Entity Creation
    description: Detects attempts to create scripts, flows, apps, or raw_apps from Operator accounts via the Windmill API, indicating a potential exploitation of CVE-2026-22683.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Windmill Job Execution of Newly Created Entities
    description: Detects the execution of Windmill jobs that were created recently, which may be related to exploitation of CVE-2026-22683.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Windmill, a low-code internal tool platform, contains a critical missing authorization vulnerability, tracked as CVE-2026-22683, affecting versions 1.56.0 through 1.614.0. The vulnerability stems from a failure to properly enforce role-based access controls within the backend API. Specifically, users assigned the "Operator" role, who are intended to have limited privileges and be restricted from creating or modifying entities, can bypass these restrictions.  This allows Operators to create and…
