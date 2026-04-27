---
title: Detection of Python Base64 Encoded Execution on Linux
slug: 2024-01-python-base64-linux
description: This brief focuses on detecting the execution of Python one-liners utilizing base64 decoding functions on Linux systems, a technique employed by malicious actors to obfuscate and execute payloads, thereby evading traditional security measures.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - execution
  - defense-evasion
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://docs.python.org/3/library/base64.html
  - https://www.virustotal.com/gui/file/bc43e925d7b4b74319f6e74e836a96f1997ba404e14ac566cf12a21e9da463db/behavior
  - https://cloud.google.com/blog/topics/threat-intelligence/cybercriminals-weaponize-fake-ai-websites
rules:
  - title: Detect Python Base64 One-Liners - Linux
    description: Detects Python one-liners that use base64 decoding on Linux systems.
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
      - linux
  - title: Detect Python Base32 One-Liners - Linux
    description: Detects Python one-liners that use base32 decoding on Linux systems.
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
      - linux
rules_count: 2
---

Attackers are increasingly leveraging Python one-liners with base64 encoding on Linux systems to deliver and execute malicious payloads. This technique allows for effective obfuscation, making it harder for conventional security solutions to detect the true nature of the executed commands. The use of `base64` within Python scripts executed directly from the command line is a red flag, as it is rarely observed in standard administrative tasks but is frequently used to hide malicious intent…
