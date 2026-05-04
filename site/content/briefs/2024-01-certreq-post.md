---
title: Potential Abuse of Certreq for File Transfer via HTTP POST
slug: 2024-01-certreq-post
description: Adversaries may abuse the Windows Certreq utility to download files or upload data to a remote URL by making an HTTP POST request, potentially for command and control or exfiltration, which can be detected by monitoring process execution events.
date: "2024-01-28T20:47:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lolbin
  - command-and-control
  - exfiltration
  - certreq
vendors:
  - Microsoft
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Sysmon Event ID 1 - Process Creation
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Certreq/
rules:
  - title: Detect Certreq HTTP Post Request
    description: Detects Certreq making an HTTP POST request, which can be used for file transfer or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
      - exfiltration
    techniques:
      - T1071.001
      - T1218
      - T1567
    data_sources:
      - process_creation
      - windows
  - title: Detect Certreq Alternate File Name
    description: Detects Certreq.exe executing, identified by the original file name, making an HTTP POST request.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
      - exfiltration
    techniques:
      - T1071.001
      - T1218
      - T1567
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Certreq utility is a command-line tool used for managing certificates. Adversaries may abuse Certreq to download files from or upload data to a remote server by initiating an HTTP POST request. This behavior can be used for command and control (C2) or exfiltration. This technique leverages a legitimate system binary (LOLBin) to evade detection. Elastic has observed this behavior being detected through multiple data sources including Elastic Defend, Microsoft Defender XDR, Sysmon, SentinelOne, and Crowdstrike. This is a cross-industry threat that can affect any organization using Windows.

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2. The attacker executes Certreq.exe with the `-Post` argument to initiate an HTTP POST request.
3. The Certreq process attempts to connect to a remote server to send or receive data.
4. The remote server responds to the Certreq request, potentially delivering a file or receiving exfiltrated data.
5. The downloaded file is saved to disk (if applicable).
6. The attacker may execute the downloaded file or further process the exfiltrated data.
7. The attacker may attempt to clean up the Certreq command from command history or logs to evade detection.

## Impact

Successful exploitation could lead to the download and execution of malicious payloads, potentially compromising the affected system and network. Alternatively, sensitive data could be exfiltrated from the target environment. The impact can range from data theft and system compromise to full network intrusion, depending on the attacker's objectives and the data accessed. The severity is medium because Certreq is a legitimate tool, and its abuse requires specific command-line arguments and network activity.

## Recommendation

*   Deploy the Sigma rule "Detect Certreq HTTP Post Request" to your SIEM to identify potential abuse of Certreq for file transfer.
*   Enable Sysmon process creation logging (Event ID 1) to capture the execution of Certreq.exe and its command-line arguments, enabling detections.
*   Monitor network connections originating from Certreq.exe for unusual destinations or data transfer patterns using network connection logs.
*   Investigate any instances of Certreq.exe executing with the `-Post` argument, as this is not typical usage of the utility.
