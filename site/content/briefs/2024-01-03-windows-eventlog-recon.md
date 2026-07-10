---
title: Windows EventLog Reconnaissance Activity Detection
slug: 2024-01-03-windows-eventlog-recon
description: This detection identifies potential reconnaissance activities on Windows systems by adversaries using tools like `wevtutil.exe`, `wmic.exe`, and PowerShell cmdlets to query event logs for sensitive information.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - eventlog
  - reconnaissance
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1654
    technique_name: Event Log Discovery
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_eventlog_recon_activity_using_log_query_utilities.yml
  - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
  - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
  - https://www.group-ib.com/blog/apt41-world-tour-2021/
  - https://labs.withsecure.com/content/dam/labs/docs/f-secureLABS-tlp-white-lazarus-threat-intel-report2.pdf
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
rules:
  - title: Detect PowerShell Event Log Querying
    description: Detects PowerShell commands used to query event logs, which may indicate reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1654
    data_sources:
      - process_creation
      - windows
  - title: Detect wevtutil.exe Event Log Query
    description: Detects the use of wevtutil.exe to query event logs, a technique used for reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1654
    data_sources:
      - process_creation
      - windows
  - title: Detect WMIC Event Log Query
    description: Detects the use of wmic.exe to query event logs, a technique used for reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1654
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This analytic detects EventLog reconnaissance activity using utilities such as `wevtutil.exe`, `wmic.exe`, PowerShell cmdlets like `Get-WinEvent`, or WMI queries targeting `Win32_NTLogEvent`. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. These tools are often used by adversaries to extract usernames, IP addresses, session data, and event information for credential access or situational awareness during lateral movement. While these utilities are legitimate, execution with specific arguments or targeting sensitive logs like `Security`, `PowerShell`, or specific EventIDs (e.g., 4624, 4778) can indicate malicious intent. This activity, if confirmed malicious, allows an attacker to extract sensitive information, potentially enabling lateral movement and further compromise within the network. The references section contains links to various threat reports that describe similar reconnaissance activity in real-world attacks.

## Attack Chain

1.  The attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker executes `powershell.exe` or `pwsh.exe` to run PowerShell commands.
3.  The attacker uses `Get-WinEvent` or `Get-EventLog` cmdlets to query specific event logs, such as the `Security` or `PowerShell` event logs.
4.  Alternatively, the attacker executes `wevtutil.exe` with the `qe` (query events) or `query-events` options to retrieve event log data.
5.  The attacker might use `wmic.exe` to query `Win32_NTLogEvent` to enumerate event logs and their contents.
6.  The attacker parses the retrieved event log data, searching for sensitive information like usernames, IP addresses, and login events (Event ID 4624).
7.  The attacker uses the gathered information to identify potential targets for lateral movement or to escalate privileges.
8.  The attacker attempts to use compromised credentials to access other systems or resources within the network, furthering their objectives.

## Impact

A successful attack can lead to the compromise of sensitive information stored in Windows Event Logs. This could include user credentials, system configurations, and other valuable data. An attacker can use this information to move laterally within the network, escalate privileges, and ultimately achieve their objectives, such as data exfiltration or deploying ransomware. Successful attacks exploiting these techniques have been observed in multiple incidents, including those attributed to Lazarus Group and APT41.

## Recommendation

*   Deploy the "Windows EventLog Recon Activity Using Log Query Utilities" analytic to your SIEM and tune for your environment.
*   Enable Sysmon EventID 1 (process creation) and Windows Event Log Security 4688 to provide the necessary data for the detection.
*   Monitor process command lines for the use of `wevtutil.exe`, `wmic.exe`, and PowerShell cmdlets like `Get-WinEvent` with parameters targeting sensitive event logs as described in the rule.
*   Investigate any alerts generated by the detection, filtering out known legitimate uses by system administrators or monitoring tools to reduce false positives.
*   Review the references section for additional context on real-world attacks that utilize similar techniques.
