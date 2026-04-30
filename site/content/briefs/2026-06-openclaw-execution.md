---
title: OpenClaw Agent Suspicious Child Process Execution
slug: 2026-06-openclaw-execution
description: Malicious actors are exploiting OpenClaw, Moltbot, and Clawdbot AI coding agents via Node.js to execute arbitrary shell commands and download-and-execute commands, potentially targeting cryptocurrency wallets and credentials.
date: "2026-04-08T12:07:54Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: domain
    value: moltbot.you
  - type: domain
    value: clawbot.ai
  - type: domain
    value: clawdbot.you
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

OpenClaw (formerly Clawdbot, rebranded to Moltbot) is an AI coding assistant that can execute shell commands and scripts. Threat actors are exploiting the skill ecosystem (ClawHub) to distribute malicious skills, observed as early as January 2026, that execute download-and-execute commands, targeting cryptocurrency wallets and credentials. These skills are often obfuscated and distributed through public registries like ClawHub. The attacks leverage the AI agents' ability to execute commands through skills or prompt injection. Defenders should monitor for suspicious child processes spawned by Node.js processes running OpenClaw/Moltbot, as these may indicate malicious activity originating from compromised or malicious skills. This activity has been observed across Linux, macOS, and Windows environments.

## Attack Chain

1. A user installs the OpenClaw agent, potentially from a legitimate or typosquatted domain.
2. The user installs a malicious skill from ClawHub or is subject to a prompt injection attack.
3. The OpenClaw agent, running under Node.js, receives a command to execute a shell command.
4. The Node.js process spawns a shell process (e.g., bash, sh, cmd.exe, powershell.exe).
5. The shell process executes a command to download a payload from a remote server using tools like curl or certutil.
6. The downloaded payload is saved to disk, often with an obfuscated name.
7. The shell process executes the downloaded payload using chmod +x and ./, rundll32.exe, or powershell.exe.
8. The payload performs malicious actions such as credential theft or cryptocurrency wallet compromise.

## Impact

Compromised OpenClaw agents can lead to cryptocurrency wallet theft, credential compromise, and potential data exfiltration. A successful attack allows threat actors to gain access to sensitive data and potentially pivot to other systems on the network. The number of victims is currently unknown, but the targeting of cryptocurrency wallets suggests financially motivated actors. The observed typosquatting activity indicates a campaign to impersonate the legitimate software and trick users into installing malicious versions.

## Recommendation

*   Monitor process creation events for suspicious child processes of Node.js processes running OpenClaw/Moltbot, specifically shells and scripting interpreters, using the provided Sigma rule ([Execution via OpenClaw Agent - Linux/macOS/Windows](#execution-via-openclaw-agent---linuxmacoswindows)).
*   Block known typosquat domains (moltbot.you, clawbot.ai, clawdbot.you) at the DNS resolver based on the IOCs provided.
*   Implement application control policies to restrict the execution of unsigned or untrusted executables, mitigating the impact of downloaded payloads.
*   Review OpenClaw skill installation logs and user AI conversation history for signs of malicious activity or prompt injection attempts.
*   Enable process command-line auditing to capture the full command line of spawned processes, aiding in the identification of malicious commands.
*   Deploy the Sigma rule to detect execution of curl/certutil downloads ([OpenClaw Download Activity](#openclaw-download-activity)).
