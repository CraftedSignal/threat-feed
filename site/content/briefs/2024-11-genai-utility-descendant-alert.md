---
title: Elastic Defend Alert from GenAI Utility or Descendant
slug: 2024-11-genai-utility-descendant-alert
description: This rule detects Elastic Defend alerts originating from or directly related to GenAI coding utilities, indicating potential prompt injection, malicious skills, or supply-chain compromise.
date: "2024-11-05T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - genai
  - supply-chain
  - elastic-defend
vendors:
  - Cursor
  - Anthropic
  - Windsurf
  - Sourcegraph
  - Continue
  - Aider
  - OpenClaw
  - Moltbot
  - Clawdbot
  - Codeium
  - Tabnine
  - GitHub
products:
  - Cursor
  - Claude
  - Windsurf
  - Cody
  - Continue
  - Aider
  - OpenClaw
  - Moltbot
  - Clawdbot
  - Codeium
  - Tabnine
  - GitHub Copilot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1195/002/
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/initial_access_elastic_defend_alert_genai_utility_descendant.toml
rules:
  - title: Suspicious Process Spawned by GenAI Utility
    description: Detects suspicious processes spawned by GenAI coding assistants like Cursor, Claude, or Copilot.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1195.002
    data_sources:
      - process_creation
      - windows
  - title: OpenClaw/Moltbot/Clawdbot Process Execution
    description: Detects execution of processes associated with OpenClaw, Moltbot, or Clawdbot
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies Elastic Defend alerts where the alerted process or its direct parent is a GenAI coding or assistant utility. These utilities include applications like Cursor, Claude, Windsurf, Cody, Continue, Aider, OpenClaw, Moltbot, Clawdbot, Codeium, Tabnine, and GitHub Copilot. The rule focuses on scenarios where these tools are leveraged for malicious activities. Such activity can include prompt injection, malicious skills, or supply-chain abuse. This higher-order rule is designed to prioritize alerts for security operations teams to investigate potential compromises originating from AI-assisted development environments. The detection is based on Elastic Defend alerts and process ancestry data, requiring Elastic Stack version 9.3.0 or later.

## Attack Chain

1.  A developer installs a compromised or malicious GenAI coding assistant utility (e.g., a VS Code extension or OpenClaw skill).
2.  The utility executes a malicious script or command, either directly or through a child process.
3.  Elastic Defend generates an alert based on the detected malicious behavior (e.g., file modification, network connection, process execution).
4.  The detection rule identifies the alert and checks if the alerted process or its parent is a known GenAI utility. This check is based on process names and command-line arguments.
5.  The rule uses process ancestry information to determine if a GenAI utility is an ancestor of the alerted process.
6.  If the alerted process has a GenAI utility as an ancestor, the rule triggers an alert, indicating a potential compromise involving the GenAI tool.
7.  The attacker gains initial access and establishes a foothold within the development environment.
8.  The attacker uses the compromised GenAI tool to further their objectives, such as code injection, data exfiltration, or lateral movement.

## Impact

A successful attack can lead to the compromise of the software supply chain, injection of malicious code into projects, exfiltration of sensitive data, and unauthorized access to internal systems. The impact can range from minor disruptions to significant financial losses and reputational damage. The compromise could affect multiple developers and projects relying on the compromised GenAI tool, potentially impacting a large user base.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment. (Sigma rules)
*   Investigate any Elastic Defend alerts where the process or its parent is a known GenAI utility, focusing on the behavior that triggered the alert. (Elastic Defend Alerts)
*   Review recently installed extensions and skills in GenAI tools like Cursor and OpenClaw for suspicious activity. (Overview section)
*   Implement network and endpoint detection and response (EDR) rules to detect and block malicious activity originating from GenAI tools. (Response and remediation guidance in source)
*   Monitor process command lines for suspicious activity like download-and-execute commands, encoded commands, or unusual arguments originating from GenAI tools. (Triage and analysis guidance in source)
