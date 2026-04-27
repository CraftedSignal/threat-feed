---
title: Lucky Pasta Shellcode Loader for Windows
slug: 2026-03-lucky-pasta-shellcode-loader
description: A shellcode loader dubbed 'Lucky Pasta' employs JIT decryption, string obfuscation, dynamic library loading, fiber-based execution, and AES instruction patching to evade AV detection, retrieving shellcode via HTTP/HTTPS and executing it on Windows systems.
date: "2026-03-24T12:00:00Z"
severities:
  - high
tags:
  - shellcode
  - windows
  - jit
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://www.reddit.com/r/cybersecurity/comments/1s1a04x/i_made_a_stealthy_jitd_shellcode_loader_that_i/
  - https://www.virustotal.com/gui/file/3e5a686e50683ecde0532b387d996153286747e7fbd2954b1c931150dc013562?nocache=1
  - https://github.com/Schich/Lucky-Pasta
ioc_counts:
  hash_sha256: 1
  url: 1
rules:
  - title: Detect Shellcode Execution via Fibers
    description: Detects the creation of fibers, a technique used for stealthy shellcode execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1055
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Retrieving Shellcode via HTTP/HTTPS
    description: Detects processes making outbound HTTP/HTTPS requests that are not common browsers, potentially indicating shellcode retrieval.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A newly developed shellcode loader, referred to as "Lucky Pasta", has been published online, showcasing advanced evasion techniques targeting Windows systems. The loader, written in C and utilizing the Windows API, is designed to bypass traditional antivirus (AV) solutions through a combination of runtime shellcode decryption using a Just-In-Time (JIT) approach, obfuscation of strings indicative of malicious intent, dynamic loading of libraries commonly flagged as suspicious, execution of…
