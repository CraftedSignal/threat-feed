---
title: Windows FTP from Non-Standard Process Path Detection
slug: 2026-07-windows-ftp-non-common-path
description: This brief details a detection for suspicious FTP connections initiated by processes located in non-standard directories on Windows systems, a behavior indicative of malware like AgentTesla used for Command and Control (C2) or data exfiltration, leading to unauthorized data transfer and potential system compromise.
date: "2026-07-03T13:20:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - endpoint
  - windows
  - ftp
  - malware
  - data-exfiltration
  - command-and-control
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: FTP is often used by adversaries and malware, such as AgentTesla, for Command and Control (C2) communications to exfiltrate stolen data.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: FTP is often used by adversaries and malware, such as AgentTesla, for Command and Control (C2) communications to exfiltrate stolen data.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_file_transfer_protocol_in_non_common_process_path.yml
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla
rules:
  - title: Detect FTP Connection from Non-Standard Process Paths
    description: Detects FTP connections initiated by processes located in non-standard directories on Windows systems, indicating potential malware activity (e.g., AgentTesla) for C2 or data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.003
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

This analytic detects FTP connections initiated by processes located in non-standard installation paths on Windows systems. It leverages Sysmon EventCode 3 to identify network connections where the process image path does not match common directories like "Program Files" or "Windows\System32". This behavior is a strong indicator of malicious activity, as adversaries and malware, specifically mentioning AgentTesla, frequently utilize FTP for Command and Control (C2) communications and data exfiltration. The technique allows attackers to bypass standard defenses and operate from unexpected locations, making detection crucial. Such activity, if unaddressed, can lead to significant compromise, including unauthorized data transfer, exposure of sensitive information, and overall system integrity loss. This detection targets the network connection phase of an attack, focusing on processes that deviate from legitimate software installation conventions.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access, often via a phishing campaign (e.g., email with a malicious attachment or link), delivering malware such as AgentTesla.
2.  **Malware Execution:** The malware payload executes, typically from a temporary directory (e.g., `%TEMP%`) or a user-writable location outside of standard program installation paths.
3.  **Process Initiates Network Connection:** The malicious process, running from the non-standard path, attempts to establish an outbound network connection.
4.  **FTP Protocol Usage:** The outbound connection specifically targets the File Transfer Protocol (FTP) on port 21, or its named service "ftp".
5.  **Command and Control (C2) or Data Exfiltration:** The established FTP connection is used by the malware to communicate with an attacker-controlled server for Command and Control purposes (receiving further instructions) or to exfiltrate stolen sensitive data (e.g., credentials, documents) from the compromised system.
6.  **Data Transfer:** Sensitive information is transferred to the attacker's infrastructure via FTP, leading to data loss and potential further compromise of the victim's environment.

## Impact

Successful exploitation results in unauthorized data transfer, allowing adversaries to exfiltrate sensitive information such as credentials, financial data, or intellectual property from the compromised host. This directly exposes confidential data and severely compromises the integrity and confidentiality of the affected system and potentially the wider network. Malware like AgentTesla, known to utilize this technique, can lead to significant financial losses and reputational damage for victim organizations across various sectors. The exact number of victims is not specified, but AgentTesla campaigns are widespread, impacting organizations globally.

## Recommendation

*   Deploy the Sigma rule "Detect FTP Connection from Non-Standard Process Paths" provided in this brief to your SIEM and tune for your environment.
*   Enable Sysmon Event ID 3 (Network Connection) logging on all Windows endpoints to ensure the necessary telemetry for this detection is collected.
*   Establish a baseline of legitimate third-party applications that utilize FTP from non-standard directories and create exclusions to reduce false positives, as mentioned in the falsepositives section of the rule.
