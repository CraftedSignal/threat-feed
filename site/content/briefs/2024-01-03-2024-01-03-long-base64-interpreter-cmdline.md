---
title: Long Base64 Encoded Command via Scripting Interpreter
slug: 2024-01-03-long-base64-interpreter-cmdline
description: Detection of oversized command lines used by Python, PowerShell, Node.js, or Deno interpreters containing base64 decoding or encoded-command patterns, indicating potential evasion and malicious execution.
date: "2024-01-03T17:00:00Z"
severities:
  - high
tags:
  - defense-evasion
  - execution
  - scripting-interpreter
  - base64
  - command-line
vendors:
  - Elastic
products:
  - Elastic Endpoint
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_long_base64_encoded_interpreter_command_line.toml
rules:
  - title: Detect Long Base64 Encoded Command via Scripting Interpreter
    description: Detects scripting interpreters (PowerShell, Python, Node.js, Deno) executing long command lines containing base64-encoded payloads.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
      - T1059.006
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: Detect Long Base64 Encoded Command via Scripting Interpreter (Linux)
    description: Detects scripting interpreters (Python, Node.js, Deno) executing long command lines containing base64-encoded payloads on Linux.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.006
      - T1059.007
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This rule identifies the execution of scripting interpreters (Python, PowerShell, Node.js, and Deno) with unusually long command lines containing base64 encoded payloads. The rule focuses on scenarios where the initial `process.command_line` field is ignored due to its excessive length, but the complete command line is still available in `process.command_line.text`. Attackers leverage this technique to evade traditional command-line inspection and execute malicious content across Windows…
