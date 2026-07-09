---
title: AI-Coded Malware Used for Active Directory Enumeration and Exfiltration
slug: 2026-07-ai-coded-ad-enumeration
description: A threat actor was observed in early June 2026 using AI-generated PowerShell scripts for Active Directory enumeration and then deploying s5cmd for data exfiltration after gaining initial access via RDP, indicating a shift towards AI-augmented tradecraft for rapid and aggressive campaigns.
date: "2026-07-09T20:26:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ai-generated-malware
  - active-directory
  - enumeration
  - powershell
  - data-exfiltration
  - windows
  - ransomware-precursor
vendors:
  - Microsoft
products:
  - Windows Server
  - Active Directory
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The attack kicked off when the threat actor established RDP access (...) onto a domain-joined Windows Server with a set of pre-compromised credentials.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1021
    technique_name: Remote Services
    evidence: The attack kicked off when the threat actor established RDP access (...) onto a domain-joined Windows Server
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Within minutes of establishing the RDP session, the attacker dropped and executed their bespoke, AI-generated payload (C:\ProgramData\Untitled1.ps1).
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: This was their opening move, to map the Active Directory environment (...) to systematically dump AD Users, Computers, and Domains
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: The script begins by attempting to identify the domain and the primary Domain Controller.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1135
    technique_name: Network Share Discovery
    evidence: They deployed SharpShares.exe, a known enumeration tool, deliberately filtering out common administrative shares to hunt for further user-accessible data repositories.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The script (...) mapped users, computers, and domains, before creating a directory and exporting out a number of files, and finally creating AD_Report.html
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Roughly half an hour later, they deployed C:\ProgramData\s5cmd.exe. s5cmd is a legitimate, high-speed command-line tool for Amazon S3 operations, which we have seen being abused frequently for data exfiltration.
    confidence_band: high
references:
  - https://www.huntress.com/blog/ai-coded-malware-vibe-coding-active-directory
iocs:
  - type: filename
    value: Untitled1.ps1
  - type: filename
    value: s5cmd.exe
  - type: filename
    value: SharpShares.exe
  - type: filepath
    value: C:\ProgramData\Untitled1.ps1
  - type: filepath
    value: C:\ProgramData\s5cmd.exe
  - type: filepath
    value: C:\ProgramData\SharpShares.exe
  - type: filename
    value: AD_Report.html
ioc_counts:
  filename: 4
  filepath: 3
rules:
  - title: Detect Suspicious Tool Execution from C_ProgramData
    description: Detects the execution of known attacker tools (s5cmd.exe, SharpShares.exe) from the C:\ProgramData\ directory, a common staging area for adversaries.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
      - execution
      - exfiltration
    techniques:
      - T1005
      - T1041
      - T1059
      - T1087
      - T1135
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Script Execution from C_ProgramData
    description: Detects PowerShell or pwsh.exe executing a script from the C:\ProgramData\ directory, often used by attackers as a staging area.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.005
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious PowerShell Active Directory Enumeration
    description: Detects the execution of multiple Active Directory enumeration commands via PowerShell, as observed with AI-generated reconnaissance scripts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
      - T1069.001
      - T1069.002
      - T1087.001
      - T1087.002
    data_sources:
      - powershell
      - windows
rules_count: 3
---

In early June 2026, unnamed threat actors were observed utilizing AI-generated PowerShell scripts, referred to as "vibe-coded" malware, to execute Active Directory (AD) enumeration during an incident. This new approach enables cybercriminals to rapidly develop bespoke, single-use scripts, shifting the threat landscape by prioritizing aggression and speed over stealth. The observed attack initiated with RDP access to a domain-joined Windows Server, followed by the deployment of a custom PowerShell script (`Untitled1.ps1`) for AD reconnaissance and subsequent use of `s5cmd.exe` for potential data exfiltration and `SharpShares.exe` for further share enumeration. This incident highlights the evolving nature of cyberattacks, where AI augmentation accelerates traditional attack chains, making it crucial for defenders to focus on detecting fundamental attack behaviors rather than solely relying on signatures of known tooling.

## Attack Chain

1. **Initial Access**: A threat actor established RDP access on a domain-joined Windows Server using pre-compromised credentials, with context suggesting initial access via a VPN.
2. **Tool Staging**: The attacker created a staging directory within `C:\ProgramData\` to store and operate their toolsets.
3. **AI-Generated Reconnaissance Script Deployment**: An AI-generated PowerShell script, `C:\ProgramData\Untitled1.ps1`, was deployed to the staging directory.
4. **Active Directory Enumeration**: The `Untitled1.ps1` script was executed to perform aggressive Active Directory enumeration, identifying domain controllers and mapping users, computers, and domains.
5. **Data Collection and Reporting**: The `Untitled1.ps1` script proceeded to create a directory, export collected AD information into various files, and generate an `AD_Report.html` to summarize the enumeration process.
6. **Data Exfiltration Preparation/Execution**: `C:\ProgramData\s5cmd.exe`, a legitimate Amazon S3 command-line tool known for data exfiltration, was deployed and likely executed for high-speed data transfer.
7. **Secondary Network Discovery**: `SharpShares.exe`, a known enumeration tool, was deployed and executed to hunt for further user-accessible data repositories by filtering common administrative shares.

## Impact

The observed incident involved a compromise of a domain-joined Windows Server, leading to extensive Active Directory enumeration and subsequent data exfiltration attempts. If successful, such attacks can rapidly lead to deeper network compromise, privilege escalation, and significant data loss, enabling further damaging campaigns by threat actors who prioritize aggression and speed over stealth. The use of AI-generated, single-use scripts makes traditional signature-based detections less effective, increasing the risk of successful exploitation and prolonged dwell times before detection.

## Recommendation

* Enable and analyze PowerShell script block logging (Event ID 4104) to activate the detection rules for AD enumeration.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious tool execution and PowerShell activity from non-standard locations like `C:\ProgramData\`.
* Implement robust RDP security controls, including multi-factor authentication and strong password policies, to prevent initial access via compromised credentials, as described in the initial access stage.
* Monitor for process creation events originating from `C:\ProgramData\` for executables like `s5cmd.exe` and `SharpShares.exe`.
* Continuously monitor for suspicious Active Directory enumeration commands, especially when executed by non-administrative accounts or from unusual processes, as detailed in the detection rules.
