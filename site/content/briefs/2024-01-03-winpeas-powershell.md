---
title: WinPEAS PowerShell Script Execution Detection
slug: 2024-01-03-winpeas-powershell
description: This brief documents the detection of the WinPEAS PowerShell script execution on Windows systems, a tool commonly used for identifying privilege escalation paths by identifying specific function names used within the script.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - post-exploitation
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1007
    technique_name: System Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1590
    technique_name: Gather Victim Network Information
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1615
    technique_name: Bypass Network Trust Discovery
references:
  - https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1
rules:
  - title: Detect WinPEAS PowerShell Script Execution
    description: Detects the execution of the WinPEAS PowerShell script via default function names used within the script.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1007
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect WinPEAS PowerShell Script Block Logging
    description: Detects the execution of the WinPEAS PowerShell script through script block logging via default function names used within the script.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1007
      - T1068
    data_sources:
      - powershell_script
      - windows
rules_count: 2
---

WinPEAS (Windows Privilege Escalation Awesome Script) is a post-exploitation tool used to automate the identification of potential privilege escalation paths on Windows systems, similar to its Linux counterpart, linpeas.sh. This detection focuses on identifying the execution of WinPEAS through PowerShell script block logging, specifically by detecting the use of default function names commonly found within the script, such as `returnHotFixID`, `Start-ACLCheck`, `UnquotedServicePathCheck`, and `Get-ClipBoardText`. Detecting WinPEAS usage can alert defenders to potential reconnaissance and privilege escalation attempts by attackers who have already gained initial access to a system.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a Windows system, potentially through exploitation of a vulnerability or compromised credentials.
2.  Execution: The attacker executes a PowerShell script, which may be directly run or downloaded and executed.
3.  Reconnaissance: The attacker executes the WinPEAS PowerShell script on the compromised system.
4.  Privilege Escalation Checks: WinPEAS automatically enumerates the system for potential privilege escalation paths. This includes checking for unquoted service paths, accessible ACLs, and potentially sensitive information like clipboard contents. The script utilizes functions such as `UnquotedServicePathCheck`, `Start-ACLCheck`, and `Get-ClipBoardText`.
5.  Data Collection: WinPEAS collects system information to identify potential privilege escalation vulnerabilities. It uses functions like `returnHotFixID` to identify installed hotfixes.
6.  Analysis: The attacker analyzes the output from WinPEAS to identify misconfigurations or vulnerabilities that can be exploited to elevate privileges.
7.  Exploitation: The attacker exploits identified vulnerabilities or misconfigurations to escalate privileges on the system.

## Impact

Successful execution of WinPEAS indicates that an attacker has already gained a foothold on a system and is actively engaged in reconnaissance for privilege escalation opportunities. This can lead to the attacker gaining higher-level access, potentially compromising sensitive data, deploying ransomware, or establishing persistent access to the network. Organizations that fail to detect and respond to WinPEAS activity may experience significant data breaches and system compromise.

## Recommendation

*   Enable PowerShell Script Block Logging (Event ID 4104) to ensure the necessary data is available for detecting WinPEAS execution.
*   Deploy the Sigma rule `Detect WinPEAS PowerShell Script Execution` to your SIEM and tune for your environment.
*   Review and investigate any alerts generated by the detection rule, prioritizing systems with sensitive data or critical functions.
*   Implement access controls and patch management procedures to mitigate the privilege escalation paths that WinPEAS may identify.
