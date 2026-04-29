---
title: Suspicious Process Execution from Unusual File Paths
slug: 2024-01-03-suspicious-process-path
description: Attackers may execute malicious code from unusual file paths such as Windows fonts or debug directories to evade defenses and gain unauthorized access, as detected by endpoint detection and response (EDR) agents.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - defense-evasion
  - persistence
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - https://twitter.com/pr0xylife/status/1590394227758104576
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
rules:
  - title: Suspicious Process Executing from Common Non-Executable Paths
    description: Detects processes running from suspicious file paths, often used by attackers to hide malicious executables.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Original File Name in Non-Executable Paths
    description: Detects processes with a suspicious original file name executing from suspicious file paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the tactic of executing processes from suspicious file paths within Windows environments, a common technique used by adversaries to bypass security controls and execute malicious code without requiring elevated privileges. This activity is often observed in post-exploitation scenarios, where attackers have already gained initial access and are attempting to establish persistence or escalate their privileges. Attackers often leverage these unconventional locations to avoid detection by traditional security solutions that rely on whitelisting or reputation-based analysis. The detection focuses on identifying processes running from paths like `\Windows\Fonts\`, `\Users\Public\`, `\Windows\Debug\`, and others, as these are not typically associated with legitimate software execution. This technique has been associated with malware families like AsyncRAT, RedLine Stealer, and LockBit Ransomware.

## Attack Chain

1.  Initial access is gained through phishing, exploitation of a vulnerability, or other means.
2.  The attacker uploads or creates a malicious executable or script (e.g., PowerShell script) in a suspicious directory such as `C:\Windows\Fonts\`.
3.  The attacker uses a dropper or loader to execute the malicious file. This can be achieved through various methods, including command-line execution or scheduled tasks.
4.  The malicious process begins execution from the unusual file path.
5.  The process performs malicious activities, such as downloading additional payloads, establishing command and control (C2) communication, or conducting reconnaissance.
6.  The attacker leverages the compromised process to escalate privileges or move laterally within the network.
7.  Data exfiltration or encryption may occur, depending on the attacker's objectives.
8.  The attacker attempts to maintain persistence by creating scheduled tasks or modifying registry keys to ensure the malicious process restarts upon system reboot.

## Impact

Successful execution of malicious code from unusual file paths can lead to a variety of negative impacts, including system compromise, data theft, and ransomware infection. Organizations may experience data breaches, financial losses, and reputational damage. The references indicate this technique is associated with various malware families, including information stealers, remote access trojans (RATs), and ransomware, affecting numerous organizations across different sectors.

## Recommendation

*   Enable process creation logging (Event ID 4688 or Sysmon Event ID 1) to capture process execution events, including the process path, command line, and parent process information to enable the rules below.
*   Deploy the Sigma rule "Suspicious Process Executing from Common Non-Executable Paths" to your SIEM to detect processes running from unusual file paths. Tune the rule to filter out any legitimate exceptions in your environment.
*   Investigate any alerts generated by the Sigma rule, paying close attention to the process name, command line, and parent process.
*   Implement application control policies to restrict the execution of unauthorized software in your environment.
*   Monitor network traffic for suspicious outbound connections originating from processes running from unusual file paths.
