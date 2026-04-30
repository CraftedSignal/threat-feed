---
title: UNC6692 Combines Social Engineering, Malware, and Cloud Abuse
slug: 2026-04-unc6692-social-engineering
description: UNC6692 is a newly discovered, financially motivated threat actor that combines social engineering via Microsoft Teams, custom malware named SNOWBELT, and abuse of legitimate AWS S3 cloud infrastructure in its attack campaigns to steal credentials and prepare for data exfiltration.
date: "2026-04-28T14:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UNC6692
tags:
  - social-engineering
  - malware
  - cloud-abuse
  - credential-theft
  - lateral-movement
vendors:
  - Microsoft
  - Google
  - Amazon
products:
  - Microsoft Teams
  - Chromium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://www.darkreading.com/cloud-security/unc6692-social-engineering-malware-cloud-abuse
rules:
  - title: Detect AutoHotKey Execution from Suspicious Location
    description: Detects the execution of AutoHotKey (AutoHotkey.exe) from unusual or temporary directories, which may indicate the execution of a downloaded malicious script.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious RDP Connection to Internal Servers
    description: Detects RDP connections initiated from potentially compromised workstations to internal servers, which may indicate lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

UNC6692 is a newly tracked, financially motivated threat group that employs a multi-stage intrusion campaign combining persistent social engineering and custom modular malware. The actor begins by flooding a target's email inbox before contacting them via Microsoft Teams, posing as help desk personnel to resolve the issue. This leads to a phishing attack where victims are tricked into downloading and executing malicious payloads. UNC6692 abuses legitimate cloud infrastructure, specifically AWS S3 buckets, for payload delivery, command and control (C2), and data exfiltration, allowing them to bypass traditional network reputation filters. The group's operations are focused on gaining access and stealing credentials for further actions, ultimately aiming to exfiltrate data of interest from compromised systems. The initial campaign was observed in late December.

## Attack Chain

1. The attacker floods a target's email inbox to create a sense of urgency.
2. The attacker contacts the target via Microsoft Teams, impersonating help desk personnel.
3. The attacker sends a phishing link via Teams, promising a local patch to fix the email spamming issue.
4. The target clicks the link, which downloads a renamed AutoHotKey binary and an AutoHotkey script from a threat actor-controlled AWS S3 bucket.
5. Execution of the AutoHotKey binary automatically runs the script, initiating reconnaissance commands and installing the SNOWBELT malicious Chromium browser extension.
6. SNOWBELT facilitates the download of additional tools, including the Snowglaze Python tunneler, the Snowbasin Python bindshell (used as a persistent backdoor), additional AutoHotkey scripts, and a portable Python executable with required libraries.
7. The attacker uses a Python script to scan the local network for ports 135, 445, and 3389 and enumerate local administrator accounts.
8. The attacker uses a local administrator account to initiate an RDP session via Snowglaze from the compromised system to a backup server, then dumps LSASS process memory and uses pass-the-hash to move laterally to the domain controller.

## Impact

The UNC6692 attack leads to the compromise of targeted systems, credential theft, and potential data exfiltration. If successful, the attacker gains control over the domain controller, allowing them to access sensitive information and potentially cause significant damage to the organization. The abuse of AWS S3 buckets allows the threat actor to blend in with legitimate cloud traffic, making detection more difficult. The financial motivation suggests that stolen credentials and data could be used for further malicious activities, such as ransomware attacks or sale on the dark web.

## Recommendation

*   Monitor for AutoHotKey execution, especially when associated with downloads from unusual locations like AWS S3 buckets, to detect initial payload execution (see Sigma rule below).
*   Implement network monitoring to detect unusual RDP connections initiated from compromised systems to internal servers, as this is a key lateral movement technique used by UNC6692 (see Sigma rule below).
*   Monitor for the installation of new Chromium extensions, especially those not distributed through the Chrome Web Store, as this is how the SNOWBELT malware is deployed.
*   Monitor for the use of Python scripts to scan the local network for open ports (135, 445, 3389) and enumerate local administrator accounts.
*   Investigate any Microsoft Teams messages delivering links that promise to fix technical problems, as this is the initial social engineering tactic used by UNC6692.
