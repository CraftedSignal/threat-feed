---
title: CikaBika Bot RAT Exploits Discord for Command and Control
slug: 2026-10-cikabika-bot
description: CikaBika Bot is a Rust-based Remote Access Trojan (RAT) delivered via phishing that utilizes Discord for command-and-control and Ngrok for exfiltration of sensitive victim data.
date: "2026-10-15T11:56:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - malware
  - rat
  - discord
  - phishing
vendors:
  - Microsoft
products:
  - Edge
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Victims receive a PDF file containing a disk image with a Windows shortcut (LNK) posing as a Word document.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: The script then attempts to move the DLL into the protected Edge directory to bypass Windows’s User Account Control (UAC).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: the attackers likely attempt to sideload the malicious code through DLL search-order hijacking by exporting functions associated with Microsoft’s debugging library.
    confidence_band: high
rules:
  - title: Detect Suspicious PowerShell Execution from LNK
    description: Detects the execution of PowerShell via a shortcut file (LNK), often used as an initial entry point in the CikaBika Bot campaign.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy PowerShell LNK detection rule
      owner: Detection Engineering
      due: 24h
      evidence: Source identifies LNK-based phishing as the initial vector.
  hunt_leads:
    - lead: Search for unsigned DLLs or unexpected DLL files within Microsoft Edge installation directories
      technique_id: T1574.002
      data_needed:
        - File system audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers sideload a Rust DLL into the Edge directory.
  mitigation_plan:
    - priority: short_term
      action: Restrict egress traffic to Ngrok domains and analyze Discord traffic patterns
      owner: Network Security
      addresses: C&C and Exfiltration
      evidence: Malware uses Discord for C&C and Ngrok for exfiltration.
---

CikaBika Bot is a modular Remote Access Trojan (RAT) written in Rust that leverages legitimate cloud services to facilitate malicious operations. The malware is distributed through phishing campaigns using document-themed lures, specifically PDF files that contain disk images with malicious Windows shortcuts (LNK). Once activated, the malware employs a Nim-based loader to deploy a Rust DLL, which is subsequently sideloaded into the Microsoft Edge directory to bypass User Account Control (UAC) and maintain persistence.

The CikaBika Bot is designed for full-system surveillance, allowing attackers to conduct reconnaissance, terminate processes, stream video, and capture screenshots. The RAT establishes command-and-control (C&C) by registering the infected host with Discord channels. Data exfiltration, particularly of compressed ZIP archives containing stolen documents, is performed via Ngrok tunnels. This combination of Discord and Ngrok demonstrates a strategy of repurposing trusted infrastructure to evade network security controls.

## Attack Chain

1. Phishing: Victim receives an email containing a PDF file that includes a disk image with a malicious Windows shortcut (LNK).
2. Execution: Upon opening the LNK file, the malware displays a decoy document while executing a hidden PowerShell command.
3. Payload Staging: The hidden PowerShell process decodes and executes an embedded Nim-based loader.
4. Persistence and UAC Bypass: The loader deploys a Rust DLL to the Microsoft Edge directory, utilizing DLL search-order hijacking against Microsoft debugging libraries to achieve elevated privileges.
5. C&C Initialization: The CikaBika Bot registers the compromised host with a specific Discord channel for communication.
6. Reconnaissance: The bot harvests system configuration, running processes, and network details, and captures system screenshots.
7. Exfiltration: The bot compresses target directories into ZIP files and exfiltrates them using the Ngrok utility.

## Impact

The CikaBika Bot provides attackers with comprehensive surveillance capabilities, including live streaming and camera control. Successful exploitation leads to the loss of sensitive documents, system information, and potential lateral movement or persistent monitoring. While specific victim counts are not disclosed, the use of targeted phishing lures suggests intent for high-value reconnaissance and data theft against organizations using Microsoft Windows environments.

## Recommendation

* Deploy Sigma rules to detect the creation of LNK files that launch PowerShell from non-standard locations or with hidden window flags.
* Monitor for process execution originating from the 'C:\Program Files (x86)\Microsoft\Edge' or 'C:\Program Files\Microsoft\Edge' directories that are not signed by Microsoft.
* Restrict the use of unauthorized remote access and tunneling utilities like Ngrok in the corporate environment via firewall or proxy egress filtering.
* Configure EDR solutions to alert on DLL sideloading patterns targeting system directories, particularly focusing on Microsoft debugging library exports.
* Implement blocklists for known Discord-based C&C traffic patterns where possible; focus on identifying anomalous traffic volumes to 'discord.com' or specific subdomains associated with bot activity.
