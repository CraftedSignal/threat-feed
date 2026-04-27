---
title: PraisonAI UI Hardcoded Approval Mode Leads to Remote Code Execution
slug: 2024-01-09-praisonai-rce
description: A vulnerability in PraisonAI allows authenticated users to execute arbitrary shell commands due to a hardcoded approval setting in the Chainlit UI modules, overriding administrator configurations and bypassing intended approval gates; insufficient command sanitization allows for destructive command execution, leading to confidentiality breach, integrity compromise, and availability impact on the server.
date: "2026-04-10T19:25:49Z"
severities:
  - critical
tags:
  - rce
  - command-injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qwgj-rrpj-75xm
rules:
  - title: Detect Suspicious PraisonAI Command Execution
    description: Detects suspicious command execution by PraisonAI, focusing on commands like curl or wget used for potential data exfiltration or backdoor installation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Outbound Connection from PraisonAI
    description: Detects suspicious outbound network connections originating from the PraisonAI process, indicating potential data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

PraisonAI is vulnerable to remote code execution due to a misconfiguration in the Chainlit UI modules (`chat.py` and `code.py`). Specifically, the application hardcodes `config.approval_mode = "auto"`, effectively disabling the intended human-in-the-loop approval mechanism for ACP tool executions, even when administrators configure the application to require manual approval. This override occurs after the application loads administrator configurations from the `PRAISON_APPROVAL_MODE`…
