---
title: Exploitation of OpenClaw and Moltbot AI Coding Agents
slug: 2026-09-openclaw-agent-abuse
description: AI coding assistants including OpenClaw, Moltbot, and Clawdbot are being weaponized via malicious 'ClawHub' registry skills to execute unauthorized system commands and exfiltrate cryptocurrency and credential data.
date: "2026-09-18T19:15:46Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - ai-security
  - supply-chain
  - command-and-control
  - living-off-the-land
products:
  - OpenClaw
  - Moltbot
  - Clawdbot
affected_os:
  - Linux
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule identifies shells, scripting interpreters, and common LOLBins spawned by these AI agents.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Malicious skills from public registries like ClawHub have been observed executing obfuscated download-and-execute commands.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
    evidence: Malicious skills... have been observed executing obfuscated download-and-execute commands.
    confidence_band: high
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
  - title: Detect Execution via OpenClaw AI Agent
    description: Detects suspicious child processes (shells/LOLBins) spawned by OpenClaw, Moltbot, or Clawdbot AI agents running via Node.js.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block moltbot.you, clawbot.ai, and clawdbot.you at DNS level.
      owner: SOC
      due: 24h
      evidence: IOCs identified as malicious domains in source.
  hunt_leads:
    - lead: Search for child processes spawned by node processes containing 'openclaw', 'moltbot', or 'clawdbot' in command line.
      technique_id: T1059
      data_needed:
        - Endpoint process logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule logic identifies these as suspicious.
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized AI coding agents from developer workstations.
      owner: IT Operations
      evidence: Tooling identified as potential security nightmare.
---

AI-assisted coding agents, specifically OpenClaw (formerly known as Clawdbot) and its rebranded iteration Moltbot, are being actively exploited by attackers who distribute malicious "skills" through the ClawHub registry. These agents, which operate as Node.js applications, are designed to execute shell commands to assist users with development tasks. Attackers leverage prompt injection techniques or malicious skill code to trigger unintended command execution on the host machine. Once initial access via the agent is achieved, attackers utilize common system binaries (LOLBins) and scripting interpreters to perform download-and-execute operations. These campaigns primarily target cryptocurrency wallets and sensitive credentials stored on the developer's workstation. This threat highlights the security risks inherent in the extensible plugin and skill ecosystems of AI developer tools, where third-party code is executed with the privileges of the user.

## Attack Chain

1. Attacker develops or compromises a "skill" available in the ClawHub registry.
2. The target developer installs the malicious skill into their OpenClaw or Moltbot AI coding environment.
3. The agent executes the malicious skill code within the Node.js process context.
4. The malicious code triggers prompt injection or direct system command execution.
5. The Node.js process spawns a child process, such as bash, powershell.exe, or curl, to execute commands.
6. The child process downloads additional obfuscated payloads from attacker-controlled infrastructure.
7. The downloaded payload executes, targeting and exfiltrating cryptocurrency wallet files or system credentials.

## Impact

Successful exploitation allows attackers to gain unauthorized command execution on the host system, leading to the theft of cryptocurrency assets and local credentials. Multiple instances of malicious skill distribution have been observed in the ClawHub ecosystem, impacting users across Windows, macOS, and Linux platforms. The shift from Clawdbot to Moltbot has also been accompanied by increased impersonation campaigns, widening the potential victim pool to include users searching for legitimate coding assistants.

## Recommendation

* Audit the use of OpenClaw, Moltbot, and Clawdbot within the development environment and establish a blocklist if these tools are not approved for use.
* Implement endpoint detection to monitor for suspicious child processes spawned by Node.js, specifically targeting shells and network-fetching binaries.
* Block network traffic to identified malicious typosquatted domains (moltbot.you, clawbot.ai, clawdbot.you) at the organizational DNS resolver or firewall.
* Deploy the provided Sigma rule to detect unauthorized shell execution initiated by AI agent processes.
* Rotate secrets, API keys, and cryptocurrency wallet keys if an infected workstation is identified.
