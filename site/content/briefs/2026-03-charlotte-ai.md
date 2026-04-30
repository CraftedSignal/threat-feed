---
title: CrowdStrike Charlotte AI AgentWorks for Agentic SOC Transformation
slug: 2026-03-charlotte-ai
description: CrowdStrike's Charlotte AI AgentWorks facilitates the development and deployment of AI-driven security agents within the SOC, aiming to enhance analyst capabilities through automated and orchestrated responses to threats.
date: "2026-03-28T09:13:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - agentic-soc
  - ai-security
  - automation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Suspicious PowerShell Encoded Command Execution
    description: Detects PowerShell execution with Base64 encoded commands, often used by attackers to evade detection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Scheduled Task Creation via Command Line
    description: Detects the creation of scheduled tasks via the command line, a common persistence technique.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has introduced Charlotte AI AgentWorks, a platform designed to enable the development and orchestration of AI-powered security agents within the Security Operations Center (SOC). Launched in March 2026, the platform aims to shift analysts from manual firefighting to strategic oversight by automating tasks and enabling context-aware responses. Charlotte AI AgentWorks integrates with leading AI models from Anthropic, NVIDIA, and OpenAI, and provides twelve pre-built agents for tasks like triage and malware analysis. The platform intends to foster collaboration and innovation in agentic security, offering free AI credits to encourage adoption and experimentation among CrowdStrike customers. This initiative is driven by the increasing speed and sophistication of cyberattacks, requiring security operations to leverage AI for faster and more effective threat response.

## Attack Chain

This brief focuses on the capabilities of Charlotte AI AgentWorks as a defensive tool. Therefore, the attack chain describes hypothetical scenarios where such a tool could be deployed to counter an attack.

1.  **Initial Access:** An attacker gains initial access via a phishing email containing a malicious attachment (e.g., a weaponized document).
2.  **Execution:** The user opens the malicious attachment, which executes a PowerShell script designed to download a second-stage payload.
3.  **Persistence:** The PowerShell script creates a scheduled task to ensure the payload executes regularly, even after a system reboot.
4.  **Defense Evasion:** The attacker attempts to disable or bypass security controls (e.g., disabling Windows Defender) to avoid detection.
5.  **Command and Control:** The downloaded payload establishes a connection to a command-and-control (C2) server, allowing the attacker to issue commands and exfiltrate data.
6.  **Lateral Movement:** The attacker uses compromised credentials or exploits vulnerabilities to move laterally within the network, targeting critical systems and data.
7.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the compromised systems to an external server under their control.
8.  **Impact:** The attacker encrypts critical data, demanding a ransom for its decryption.

## Impact

If an attack succeeds, organizations may experience significant data breaches, financial losses, and reputational damage. The rise of AI-powered adversaries is accelerating the speed of attacks, with breakout times collapsing to as fast as 27 seconds. Successful attacks may lead to ransomware deployment, intellectual property theft, and disruption of critical services. Organizations are looking to AI-driven security solutions, such as Charlotte AI AgentWorks, to enhance their defenses and mitigate these risks.

## Recommendation

*   Deploy and configure CrowdStrike Falcon to collect relevant telemetry data for the rules below, enabling detection of suspicious activities indicative of attack chains.
*   Deploy the provided Sigma rules to detect potentially malicious PowerShell execution and scheduled task creation.
*   Utilize Charlotte AI AgentWorks's pre-built agents for malware analysis and triage to accelerate incident response.
*   Experiment with Charlotte AI using the free AI credits to convert natural language into governed automation, improving security workflows.
