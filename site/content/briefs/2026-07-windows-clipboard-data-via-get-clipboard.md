---
title: Detection of PowerShell Get-Clipboard for Data Collection
slug: 2026-07-windows-clipboard-data-via-get-clipboard
description: This brief describes the detection of adversaries leveraging the `Get-Clipboard` PowerShell commandlet, identified through PowerShell Script Block Logging (EventCode 4104), to steal sensitive information such as credentials or PII from the Windows clipboard during the collection phase of an attack, potentially leading to unauthorized access and further compromise.
date: "2026-07-03T13:35:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - collection
  - endpoint
  - powershell
  - data-theft
  - post-exploitation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1115
    technique_name: Clipboard Data
    evidence: The following analytic detects the execution of the PowerShell command 'Get-Clipboard' to retrieve clipboard data.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1115/
  - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
  - https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_clipboard_data_via_get_clipboard.yml
rules:
  - title: Detect PowerShell Get-Clipboard Execution
    description: Detects the execution of the PowerShell commandlet 'Get-Clipboard' within PowerShell script block logs, indicating potential attempts to collect sensitive data from the user's clipboard.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1115
    data_sources:
      - powershell_script
      - windows
rules_count: 1
---

This threat brief focuses on the detection of the PowerShell commandlet `Get-Clipboard` being executed on Windows endpoints. This technique is commonly employed by adversaries in the post-exploitation phase to collect sensitive data that users may have recently copied to their clipboard, including usernames, passwords, API keys, or other confidential information. Detection relies on PowerShell Script Block Logging (EventCode 4104), which records the execution of PowerShell commands and scripts. The presence of `Get-Clipboard` in these logs is a strong indicator of attempted information theft. While the source does not detail a specific campaign, the technique is a fundamental component of various malware families, including those like Prestige Ransomware and BlankGrabber Stealer, which aim to exfiltrate valuable data from compromised systems. Detecting this activity is crucial for identifying data collection efforts before sensitive information can be fully exfiltrated and misused.

## Attack Chain

1.  **Initial Access**: An adversary typically gains initial access to a target system through common vectors such as spearphishing with a malicious attachment, exploitation of a public-facing application vulnerability, or supply chain compromise.
2.  **Execution**: Following initial access, the adversary executes a payload, often a script or malware, on the victim's machine to establish a foothold and begin operations. This payload might be delivered via a legitimate process or a malicious downloader.
3.  **Persistence**: To maintain access to the compromised system, the adversary establishes persistence mechanisms, such as modifying registry run keys, creating scheduled tasks, or installing malicious services.
4.  **Discovery**: The attacker performs internal reconnaissance, using tools or scripts to gather information about the compromised system, network configuration, and user activities, identifying potential sources of valuable data.
5.  **Collection - Clipboard Data**: During the collection phase, the adversary executes the `Get-Clipboard` PowerShell commandlet on the compromised endpoint. This command retrieves the current content of the Windows clipboard, which can contain sensitive user data like credentials, payment information, or PII.
6.  **Command and Control**: The collected clipboard data, potentially after encoding or encryption, is then exfiltrated from the compromised host to an attacker-controlled command and control (C2) server over various protocols (e.g., HTTP, DNS).
7.  **Impact**: The exfiltrated clipboard data is analyzed by the attacker. This information can be used for further system compromise, account takeover across other services, lateral movement within the network, or direct financial fraud.

## Impact

Successful exploitation of this technique can lead to severe data breaches, encompassing the theft of sensitive credentials, personally identifiable information (PII), or proprietary corporate data. While the brief does not specify a victim count or particular sectors, `Get-Clipboard` is a generalized tactic applicable across all industries. The immediate impact is the compromise of information that was temporarily stored in the clipboard, which could directly facilitate unauthorized access to user accounts, internal systems, or even lead to financial losses if payment card information or banking credentials are exfiltrated. Long-term consequences include reputational damage, regulatory fines, and extensive remediation costs.

## Recommendation

*   Enable PowerShell Script Block Logging (EventCode 4104) on all Windows endpoints to ensure the necessary telemetry for detection. Refer to the `how_to_implement` section in the source for guidance.
*   Deploy the provided Sigma rule "Detect PowerShell Get-Clipboard Execution" to your SIEM and tune it for your environment to detect `Get-Clipboard` usage.
*   Implement security awareness training for users, emphasizing the risks of copying sensitive information (like passwords) to the clipboard, especially in untrusted environments.
