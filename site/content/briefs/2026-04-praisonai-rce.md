---
title: PraisonAI Agent Subprocess Sandbox Escape via Frame Traversal
slug: 2026-04-praisonai-rce
description: A critical vulnerability (CVE-2026-39888) in PraisonAI agents through version 1.5.113 allows remote code execution via a sandbox escape in the `execute_code` function due to insufficient attribute blocking, enabling privilege escalation, credential access, and lateral movement.
date: "2026-04-08T19:17:28Z"
severities:
  - critical
tags:
  - sandbox-escape
  - remote-code-execution
  - python
  - praisonai
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qf73-2hrx-xprp
rules:
  - title: Detect PraisonAI Agent Sandbox Escape Attempt via Frame Traversal
    description: Detects attempts to exploit the PraisonAI agent sandbox escape vulnerability by identifying code that accesses frame attributes within the sandboxed environment.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Agent Subprocess Execution
    description: Detects execution of the praisonaiagents python_tools subprocess, which may indicate exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists in PraisonAI agents, specifically affecting the `execute_code` function within the `praisonaiagents.tools.python_tools` module. This flaw allows an attacker to escape the intended subprocess sandbox environment due to an incomplete blocklist of attributes.  The vulnerability stems from the `sandbox_mode="sandbox"` default configuration, intended to restrict user-supplied code execution. The AST-based blocklist designed to prevent access to dangerous attributes is…
