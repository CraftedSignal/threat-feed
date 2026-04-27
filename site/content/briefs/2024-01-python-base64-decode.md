---
title: Detection of Python One-Liners with Base64 Decoding
slug: 2024-01-python-base64-decode
description: This brief outlines a method to detect malicious use of Python one-liners employing base64 decoding to execute obfuscated payloads, a common tactic for evading traditional security measures.
date: "2024-01-03T14:30:00Z"
severities:
  - high
tags:
  - attack.execution
  - attack.defense-evasion
  - attack.t1059.006
  - attack.t1027.010
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://docs.python.org/3/library/base64.html
  - https://www.virustotal.com/gui/file/bc43e925d7b4b74319f6e74e836a96f1997ba404e14ac566cf12a21e9da463db/behavior
  - https://cloud.google.com/blog/topics/threat-intelligence/cybercriminals-weaponize-fake-ai-websites
rules:
  - title: Detect Python Base64 Encoded Command Execution
    description: Detects Python one-liners using base64 decoding functions in command line executions, indicative of obfuscated payload execution.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1027.010
      - T1059.006
    data_sources:
      - process_creation
      - windows
  - title: Detect Alternate Python Base64 Decode Methods
    description: Detects Python one-liners using alternate base64 decoding functions in command line executions.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1027.010
      - T1059.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently leverage Python one-liners with base64 encoding to obfuscate and execute malicious code. This technique bypasses standard security measures by concealing the true nature of the payload. The abuse involves embedding base64-encoded commands within Python scripts, which are then decoded and executed at runtime. While legitimate uses of Python and base64 exist, their combination in a single command line, especially with execution flags, is a strong indicator of malicious…
