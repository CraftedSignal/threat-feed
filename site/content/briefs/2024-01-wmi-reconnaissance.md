---
title: Suspicious PowerShell Reconnaissance via WMI Queries
slug: 2024-01-wmi-reconnaissance
description: Detection of suspicious PowerShell activity using Windows Management Instrumentation (WMI) to gather system information, indicative of reconnaissance efforts by adversaries potentially leading to further exploitation or lateral movement.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - powershell
  - wmi
  - reconnaissance
  - lateral_movement
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
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
    description: Detects PowerShell scripts using WMI to gather system information, which may indicate reconnaissance activity.
    platform: sigma
    severity: high
    tactics:
      - execution
      - reconnaissance
    techniques:
      - T1059.001
      - T1592
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious WMI Reconnaissance via Cmd
    description: Detects Command Prompt using WMI to gather system information, which may indicate reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - reconnaissance
    techniques:
      - T1059.001
      - T1592
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on detecting reconnaissance activities performed through PowerShell using WMI queries. Adversaries often use WMI to gather detailed information about a compromised system, including hardware specifications, operating system details, and installed software. This information can be used to plan further attacks, such as privilege escalation or lateral movement. This detection leverages PowerShell Script Block Logging (EventCode 4104) to identify specific WMI queries that target system information classes like `Win32_Bios`, `Win32_OperatingSystem`, `Win32_Processor` and others. Identifying this behavior early can help defenders disrupt attack chains before significant damage occurs. The analytic is based on the detection logic from the Splunk Security Content project as of April 2026.

## Attack Chain

1. An attacker gains initial access to the target system, potentially through phishing or exploiting a software vulnerability.
2. The attacker executes a PowerShell script, either directly or via a command-line interpreter like `cmd.exe`.
3. The PowerShell script uses the `Get-WmiObject` cmdlet or a direct WMI query with `SELECT` to query system information.
4. Specific WMI classes are targeted, including `Win32_Bios`, `Win32_OperatingSystem`, `Win32_Processor`, `Win32_ComputerSystem`, `Win32_PnPEntity`, `Win32_ShadowCopy`, `Win32_DiskDrive`, `Win32_PhysicalMemory`, `Win32_BaseBoard`, and `Win32_DisplayConfiguration`.
5. The script collects the data returned by the WMI queries.
6. The gathered information is used to profile the system and identify potential vulnerabilities or weaknesses.
7. The attacker uses the gathered information to plan subsequent stages of the attack, like lateral movement or privilege escalation.
8. The attacker executes further commands based on the gathered information.

## Impact

Successful reconnaissance can provide attackers with a comprehensive understanding of the target environment, enabling them to tailor their attacks for maximum impact. This can lead to successful privilege escalation, lateral movement, data exfiltration, or ransomware deployment. Organizations that fail to detect and prevent reconnaissance activities are at a higher risk of experiencing significant data breaches and financial losses. The Maze ransomware group, Industroyer2, and LockBit ransomware have been observed using similar reconnaissance techniques.

## Recommendation

*   Enable PowerShell Script Block Logging on all endpoints to capture the necessary data for detection ([PowerShell Script Block Logging 4104](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba.)).
*   Deploy the Sigma rule `Detect Suspicious WMI Reconnaissance via PowerShell` to identify PowerShell scripts querying sensitive WMI classes.
*   Investigate any alerts generated by the Sigma rule, focusing on the user and process context to determine potential malicious intent.
*   Review and tune the `Recon Using WMI Class` detection filter (`recon_using_wmi_class_filter`) to reduce false positives in your environment.
