---
title: Budibase Command Injection Vulnerability in Bash Automation Step
slug: 2026-04-budibase-cmd-injection
description: A command injection vulnerability exists in Budibase's bash automation step due to insufficient sanitization, allowing attackers with automation modification access to inject arbitrary shell commands, leading to remote code execution.
date: "2026-04-04T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - rce
  - budibase
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-gjw9-34gf-rp6m
rules:
  - title: Detect Suspicious Budibase Bash Automation Command Injection Attempts
    description: Detects attempts to exploit the command injection vulnerability in Budibase's bash automation step by identifying suspicious shell commands within automation workflow configurations.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Potentially Malicious Commands Executed by Budibase
    description: Detects the execution of potentially malicious commands by the Budibase process, indicating a possible exploitation of the command injection vulnerability.
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

A command injection vulnerability has been identified in Budibase versions prior to 3.33.4, specifically within the bash automation step located in `packages/server/src/automations/steps/bash.ts`. This flaw allows an attacker with permissions to create or modify automation workflows to inject arbitrary shell commands. The vulnerability stems from the usage of `execSync` to execute user-supplied commands without adequate sanitization or validation. Input is processed through `processStringSync`…
