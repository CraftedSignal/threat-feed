---
title: GlassWorm Supply Chain Attack Using Unicode Encoding and Credential Theft
slug: 2026-03-glassworm-supply-chain
description: The GlassWorm campaign employs Unicode variation selectors to conceal malicious code within supply chain artifacts, subsequently querying a Solana wallet for C2 URLs and exfiltrating sensitive credentials.
date: "2026-03-24T14:30:00Z"
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - unicode-encoding
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s1ft8s/techniquebased_detection_for_glassworm_supply/
  - https://github.com/afine-com/glassworm-hunter
rules:
  - title: Unicode Payload Detection
    description: Detects files with high densities of Unicode variation selector characters, indicative of GlassWorm-encoded payloads.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - linux|windows|macos
  - title: GlassWorm Decoder Detection
    description: Detects the GlassWorm decoder pattern using codePointAt() with arithmetic and eval() or Function().
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.006
    data_sources:
      - process_creation
      - linux|windows|macos
rules_count: 2
---

The GlassWorm campaign, active since October 2025, targets software supply chains through malicious code concealed using Unicode variation selectors. This technique renders the payload virtually invisible in standard editors and code review processes. The attackers rotate extension IDs, npm package names, wallet addresses, and C2 infrastructure across multiple waves. A decoder component extracts the hidden bytes and executes them via `eval()` or `Function()`. The malware queries a Solana wallet…
