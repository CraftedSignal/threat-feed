---
title: PraisonAI Remote Code Execution via Malicious Workflow YAML
slug: 2024-01-03-praisonai-rce
description: 'PraisonAI is vulnerable to remote code execution; loading untrusted YAML files with `type: job` can lead to arbitrary host command execution, potentially enabling full system compromise.'
date: "2026-04-10T19:32:48Z"
severities:
  - critical
tags:
  - praisonai
  - rce
  - yaml
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-vc46-vw85-3wvm
ioc_counts:
  filename: 2
rules:
  - title: Detect PraisonAI Workflow Execution with Suspicious YAML
    description: Detects the execution of praisonai workflow commands potentially triggered by malicious YAML files
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation by Python within PraisonAI Workflow
    description: Detects file creation events potentially originating from Python code executed within a PraisonAI workflow, indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

PraisonAI is vulnerable to remote code execution via specially crafted YAML files. The vulnerability stems from the `praisonai workflow run <file.yaml>` command, which, when processing YAML files with `type: job`, executes steps through the `JobWorkflowExecutor` class in `job_workflow.py`. This execution path supports shell command execution via `subprocess.run()`, inline Python execution via `exec()`, and arbitrary Python script execution. An attacker can leverage this to inject malicious code…
