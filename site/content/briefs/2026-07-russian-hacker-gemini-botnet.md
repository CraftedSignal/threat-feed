---
title: Russian-Speaking Hacker 'bandcampro' Leverages Google Gemini CLI for Botnet Operations
slug: 2026-07-russian-hacker-gemini-botnet
description: A Russian-speaking threat actor known as 'bandcampro' is using Google's open-source Gemini CLI to manage and control a botnet of eight compromised dental clinic computers, facilitating activities such as password cracking, C2 infrastructure migration, and planning cryptocurrency fraud.
date: "2026-07-20T10:07:26Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - bandcampro
tags:
  - ai-assisted
  - botnet
  - cybercrime
  - command-and-control
  - powershell
  - credential-access
vendors:
  - Open Dental Software
products:
  - OpenDental
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The architecture involves victims issuing outbound requests to a C&C server over HTTPS to pull and run PowerShell commands staged by the threat actor on the server.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The architecture involves victims issuing outbound requests to a C&C server over HTTPS to pull and run PowerShell commands staged by the threat actor on the server.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Password cracking, which used the agent as a credential mutation engine to predict possible passwords based on an input list obtained from AntiPublic, which maintains a database of leaked credentials, and leveraged those guesses as a brute-force tool for WordPress admin panels, successfully gaining access in a handful of cases.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Send a file enumeration command to the bot
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Send reconnaissance commands to the front desk machine
    confidence_band: high
references:
  - https://thehackernews.com/2026/07/russian-speaking-hacker-uses-google.html
rules:
  - title: Detect Suspicious AI-Assisted PowerShell Execution
    description: Detects PowerShell command lines indicative of C2-driven or AI-generated malicious activity, such as downloading and executing code or performing reconnaissance, as leveraged by 'bandcampro'.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - discovery
      - execution
    techniques:
      - T1059.001
      - T1071.001
      - T1083
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

A solo Russian-speaking threat actor identified as "bandcampro" has been observed using Google's open-source Gemini CLI (Command Line Interface) to automate and manage a botnet, comprising eight computers within a dental clinic. This activity, analyzed through 200 Gemini CLI session logs between March 19 and April 21, 2026, reveals the actor leveraging AI for various malicious purposes including password cracking, setting up residential proxies, compromising WordPress merchants, and planning cryptocurrency fraud schemes. The AI acts as the primary hacking agent, consultant, and interface for the operation, significantly reducing the technical expertise and time required for the actor to set up and manage command and control (C2) infrastructure, perform botnet tasks, and debug issues. The ease of replicating the C2 operation using minimal plaintext files makes takedowns less impactful and enables a highly disposable infrastructure.

## Attack Chain

1. **Initial Compromise (Implied)**: Threat actor "bandcampro" gains initial access to eight computers within a dental clinic, forming a small-scale botnet. The specific initial access vector is not detailed in the report.
2. **AI-Assisted C&C Setup**: The actor utilizes Google Gemini CLI to interact with an AI agent, instructing it to set up and configure the initial C&C server on a Virtual Private Server (VPS), including establishing Cloudflare tunnels for communication.
3. **C&C Infrastructure Migration**: The AI agent is used to migrate the entire C&C infrastructure to a new VPS, autonomously diagnosing and resolving migration errors, WAF blocks (by adding User-Agent headers), and connectivity issues in under six minutes.
4. **Botnet Connection and Command Staging**: Compromised dental clinic machines initiate outbound HTTPS requests to the migrated C&C server, pulling and executing PowerShell commands that are staged by the threat actor on the server.
5. **Botnet Management and Reconnaissance**: The actor uses natural language instructions via the AI agent to perform botnet management tasks such as reporting active machines, sending file enumeration commands to bots, and executing reconnaissance commands on specific machines (e.g., the front desk computer).
6. **Lateral Movement/Infection**: The AI agent is prompted to generate one-line PowerShell commands, which are then used to infect additional machines within the compromised network.
7. **Data Access and Fraud Planning**: The actor accesses the dental clinic's OpenDental database on the compromised systems and uses the AI for planning further malicious activities, such as phone-based cryptocurrency fraud targeting elderly individuals in the U.S. and Canada.

## Impact

The observed impact includes the compromise of eight computers within a dental clinic, leading to potential access to sensitive patient data stored in the OpenDental database. The use of AI significantly streamlines malicious operations, reducing the resources and technical skill required for threat actors. This makes C2 infrastructure highly disposable and difficult to attribute or permanently disrupt, enabling "bandcampro" to efficiently conduct credential theft, operate residential proxies, exploit WordPress merchants, and plan large-scale cryptocurrency fraud schemes. The AI's ability to self-debug and rapidly re-establish C2 operations means that traditional takedown efforts are less effective, posing a persistent threat to targeted organizations.

## Recommendation

* Enable comprehensive PowerShell script block logging and module logging to detect suspicious command execution, as described in the `Detect Suspicious AI-Assisted PowerShell Execution` rule.
* Deploy the `Detect Suspicious AI-Assisted PowerShell Execution` Sigma rule to your SIEM and tune for your environment to identify C2-driven command execution.
* Monitor network connections for outbound HTTPS traffic from endpoints to unusual or newly observed domains and IP addresses, especially those not associated with known legitimate services.
* Implement endpoint detection and response (EDR) solutions to monitor for the execution of unusual processes or commands, particularly those initiated through scripting languages.
* Review access logs for applications like OpenDental for any unauthorized access attempts or suspicious activity originating from compromised endpoints.
