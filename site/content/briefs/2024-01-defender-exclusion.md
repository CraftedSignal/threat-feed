---
title: Windows Defender Exclusion Added or Modified via Command Line
slug: 2024-01-defender-exclusion
description: Adversaries use Add-MpPreference or Set-MpPreference commands to add exclusions in Windows Defender, allowing malicious code to execute undetected, and this activity can be detected via Endpoint Detection and Response (EDR) agents.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windowsdefender
  - exclusion
  - defense-evasion
  - endpoint
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html
  - https://app.any.run/tasks/cf1245de-06a7-4366-8209-8e3006f2bfe5/
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference?view=windowsserver2025-ps
rules:
  - title: Detect Windows Defender Exclusion Added via PowerShell
    description: Detects the use of Add-MpPreference or Set-MpPreference cmdlets in PowerShell to add exclusions to Windows Defender.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Defender Exclusion Added via Command Line
    description: Detects the use of cmd.exe to execute PowerShell commands to add exclusions in Windows Defender.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often attempt to evade detection by security tools like Windows Defender. One common technique involves adding exclusions to prevent Defender from scanning or detecting malicious files, processes, or network activity. This is often achieved by using the `Add-MpPreference` or `Set-MpPreference` PowerShell cmdlets, which can modify Defender's configuration. These commands are used to specify files, folders, or processes that Defender should ignore during scans. Once an exclusion is successfully added, malicious code can execute without being detected by Windows Defender. This is a significant concern for defenders because it directly undermines the effectiveness of the built-in antivirus solution. The activity detected here stems from endpoint telemetry and can often be associated with malware families such as Remcos RAT, AgentTesla, ValleyRAT, XWorm and others.

## Attack Chain

1. Initial Access: The attacker gains initial access through various means, such as phishing emails or exploiting vulnerabilities in software.
2. Privilege Escalation: Once inside the system, the attacker escalates privileges to gain administrative access, which is required to modify Windows Defender settings.
3. Discovery: The attacker performs reconnaissance to understand the system's configuration, including the presence and configuration of Windows Defender.
4. Defense Evasion: The attacker uses `Add-MpPreference` or `Set-MpPreference` in PowerShell to add exclusions to Windows Defender, targeting specific files, folders, or processes used by the malware. This bypasses real-time scanning and detection.
5. Execution: The attacker executes malicious code, which can now run without being detected by Windows Defender due to the added exclusions.
6. Persistence: The attacker establishes persistence by creating scheduled tasks or modifying registry keys, ensuring that the malicious code continues to run even after a system reboot. The exclusions remain in place to allow continued operation.
7. Command and Control: The malware establishes communication with a command and control (C2) server to receive further instructions and exfiltrate data.

## Impact

Successful exploitation allows attackers to bypass Windows Defender, leading to undetected malware execution and potentially enabling further malicious activities, such as data theft, ransomware deployment, or system compromise. The number of affected systems depends on the scope of the initial compromise, but the impact can be widespread if the attacker gains access to critical systems.

## Recommendation

*   Enable Sysmon process creation logging to capture the command-line arguments used when adding Defender exclusions, which is essential for triggering the rules below.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious `Add-MpPreference` or `Set-MpPreference` usage and tune them to your environment.
*   Investigate any instances of `Add-MpPreference` or `Set-MpPreference` commands, especially those initiated by unusual parent processes or users.
*   Regularly review and audit Windows Defender exclusions to identify and remove any unauthorized or suspicious entries.
*   Monitor the references for IoCs related to malware families abusing Windows Defender exclusions.
