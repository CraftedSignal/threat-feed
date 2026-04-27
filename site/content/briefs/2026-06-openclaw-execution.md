---
title: OpenClaw Agent Suspicious Child Process Execution
slug: 2026-06-openclaw-execution
description: Malicious actors are exploiting OpenClaw, Moltbot, and Clawdbot AI coding agents via Node.js to execute arbitrary shell commands and download-and-execute commands, potentially targeting cryptocurrency wallets and credentials.
date: "2026-04-08T12:07:54Z"
severities:
  - medium
tags:
  - ai-agent
  - execution
  - malware
  - credential-theft
mitre_ttps:
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
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.malwarebytes.com/blog/threat-intel/2026/01/clawdbots-rename-to-moltbot-sparks-impersonation-campaign
  - https://www.tomshardware.com/tech-industry/cyber-security/malicious-moltbot-skill-targets-crypto-users-on-clawhub
  - https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare
  - https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html
ioc_counts:
  domain: 3
rules:
  - title: Execution via OpenClaw Agent - Linux/macOS/Windows
    description: Detects suspicious child process execution from OpenClaw, Moltbot, or Clawdbot agents running via Node.js.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1071
    data_sources:
      - process_creation
      - windows|linux|macos
  - title: OpenClaw Download Activity
    description: Detects curl/certutil used to download files by OpenClaw/Moltbot agents.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows|linux|macos
rules_count: 2
---

OpenClaw (formerly Clawdbot, rebranded to Moltbot) is an AI coding assistant that can execute shell commands and scripts. Threat actors are exploiting the skill ecosystem (ClawHub) to distribute malicious skills, observed as early as January 2026, that execute download-and-execute commands, targeting cryptocurrency wallets and credentials. These skills are often obfuscated and distributed through public registries like ClawHub. The attacks leverage the AI agents' ability to execute commands…
