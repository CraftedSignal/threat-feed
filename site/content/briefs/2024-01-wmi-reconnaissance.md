---
title: Suspicious WMI Reconnaissance via PowerShell
slug: 2024-01-wmi-reconnaissance
description: This analytic detects suspicious PowerShell activity leveraging WMI to gather system information, potentially indicating reconnaissance by an attacker.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - powershell
  - wmi
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Reconnaissance
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/
  - https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba.
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
  - https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
  - https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/
  - https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
  - https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/
  - https://blogs.vmware.com/security/2022/10/lockbit-3-0-also-known-as-lockbit-black.html
rules:
  - title: Detect Suspicious WMI Reconnaissance via PowerShell
    description: Detects PowerShell scripts using WMI to gather system information.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1059.001
      - T1592
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious WMI Queries in PowerShell Script Block Logging
    description: Detects suspicious WMI queries within PowerShell script block logging, focusing on specific WMI classes indicative of reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1059.001
      - T1592
    data_sources:
      - powershell_script
      - windows
rules_count: 2
---

This detection identifies suspicious PowerShell activity where Windows Management Instrumentation (WMI) is used to query system information. Adversaries often use WMI for reconnaissance to profile compromised machines. The detection focuses on PowerShell EventCode 4104 and identifies specific WMI queries targeting system information classes such as Win32_Bios, Win32_OperatingSystem, Win32_Processor, Win32_ComputerSystem, Win32_PnPEntity, Win32_ShadowCopy, Win32_DiskDrive, Win32_PhysicalMemory, Win32_BaseBoard, and Win32_DisplayConfiguration. This activity, if confirmed malicious, allows attackers to gather detailed system information to aid further exploitation or lateral movement within a network. The detection is based on an analytic from Splunk's security content and leverages PowerShell Script Block Logging.

## Attack Chain

1.  The attacker gains initial access to the system, potentially through methods not directly observed by this detection.
2.  The attacker executes PowerShell.exe to perform reconnaissance.
3.  The attacker utilizes the `Get-WmiObject` cmdlet or `SELECT` queries within PowerShell to interact with WMI.
4.  The PowerShell script queries WMI classes such as `Win32_Bios`, `Win32_OperatingSystem`, or other classes listed in the detection, to gather information about the system hardware and software.
5.  The gathered information is processed and potentially stored or transmitted to a remote server under the attacker's control (not directly visible in this detection).
6.  The attacker analyzes the collected system information to identify potential vulnerabilities or weaknesses for further exploitation.
7.  Based on the gathered information, the attacker plans and executes lateral movement or privilege escalation attempts within the network.
8.  The final objective could be data exfiltration, ransomware deployment, or other malicious activities, leveraging the gathered system information.

## Impact

A successful reconnaissance phase allows attackers to understand the target environment, identify vulnerabilities, and plan further actions. This can lead to data breaches, system compromise, and financial loss. While specific victim numbers are not available, organizations in various sectors are potentially at risk. Successful exploitation following reconnaissance can result in significant operational disruption and reputational damage.

## Recommendation

*   Enable PowerShell Script Block Logging on all endpoints to capture the necessary data for this detection, as referenced in the "how_to_implement" section.
*   Deploy the Sigma rule "Detect Suspicious WMI Reconnaissance via PowerShell" to your SIEM and tune the filter list to reduce false positives in your environment.
*   Investigate any alerts generated by this rule, focusing on the context of the user and the destination system (dest, user_id).
*   Review the references provided for additional context on PowerShell-based attacks and WMI abuse.
