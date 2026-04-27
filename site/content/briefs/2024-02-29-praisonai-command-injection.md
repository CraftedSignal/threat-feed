---
title: PraisonAI Vulnerable to OS Command Injection
slug: 2024-02-29-praisonai-command-injection
description: PraisonAI is vulnerable to OS command injection due to the use of `subprocess.run()` with `shell=True` on user-controlled inputs, allowing attackers to inject arbitrary shell commands and potentially leading to sensitive data exfiltration or system compromise in versions prior to 4.5.121.
date: "2026-04-08T21:52:10Z"
severities:
  - critical
tags:
  - command-injection
  - rce
  - praisonai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-2763-cj5r-c79m
ioc_counts:
  domain: 1
rules:
  - title: Detect PraisonAI Command Injection via Workflow
    description: Detects command injection attempts in PraisonAI by monitoring process creations that execute PraisonAI with suspicious shell commands in workflow files.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Command Injection via Agent Configuration
    description: Detects command injection attempts in PraisonAI by monitoring process creations with shell commands in agent configuration files.
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

PraisonAI versions prior to 4.5.121 are susceptible to OS command injection. The vulnerability stems from the application's use of `subprocess.run()` with the `shell=True` parameter when executing commands derived from various user-controlled inputs. These inputs include YAML workflow definitions, agent configuration files (agents.yaml), LLM-generated tool call parameters, and recipe step configurations. This configuration allows an attacker to inject arbitrary shell commands through shell…
