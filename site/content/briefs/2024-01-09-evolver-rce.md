---
title: Evolver Remote Code Execution via Command Injection in `_extractLLM()`
slug: 2024-01-09-evolver-rce
description: A command injection vulnerability in the `_extractLLM()` function of the evolver application allows remote attackers to execute arbitrary shell commands by injecting shell metacharacters into the `corpus` parameter, leading to potential system compromise.
date: "2024-01-09T10:00:00Z"
severities:
  - critical
tags:
  - command-injection
  - rce
  - evolver
vendors:
  - Evomap
products:
  - '@evomap/evolver'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-j5w5-568x-rq53
rules:
  - title: Detect Evolver Command Injection Attempt
    description: Detects attempts to exploit the Evolver command injection vulnerability by identifying shell metacharacters within the command line of executed processes.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Curl Usage with User-Controlled Data
    description: Detects suspicious curl commands where the data being posted appears to contain shell injection characters.  This may indicate an attempt to exploit the Evolver RCE.
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

A command injection vulnerability exists in the `_extractLLM()` function within the `src/gep/signals.js` file of the evolver application, specifically in versions prior to 1.69.3. The vulnerability stems from the function's construction of a `curl` command via string concatenation, incorporating the `corpus` parameter without sufficient sanitization. This parameter, derived from user input through the `extractSignals()` function, is susceptible to shell command substitution using the `$(...)`…
