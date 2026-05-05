---
title: Cobalt Strike PowerShell Loader Detection
slug: 2024-01-cobalt-strike-powershell-loader
description: This brief details a detection for a PowerShell loader pattern commonly used with Cobalt Strike to decompress and execute payloads, often observed in scripted web delivery attacks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cobaltstrike
  - powershell
  - malware
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1608
    technique_name: Stage Payload Delivery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_cobalt_strike_powershell_loader.yml
rules:
  - title: Cobalt Strike PowerShell Loader
    description: Detects PowerShell scripts containing the Cobalt Strike PowerShell loader pattern using GzipStream for decompression.
    platform: sigma
    severity: high
    tactics:
      - cobaltstrike
      - execution
    techniques:
      - T1059.001
      - T1608
    data_sources:
      - process_creation
      - windows
  - title: Cobalt Strike PowerShell Loader via Script Block Logging
    description: Detects Cobalt Strike PowerShell loader pattern using Script Block Logging.
    platform: sigma
    severity: high
    tactics:
      - cobaltstrike
      - execution
    techniques:
      - T1059.001
      - T1608
    data_sources:
      - powershell
      - windows
rules_count: 2
---

This brief focuses on detecting the PowerShell loader pattern frequently employed by Cobalt Strike, a commercial penetration testing tool often abused by threat actors, including ransomware groups, for malicious purposes. Cobalt Strike is favored due to its stealthy and customizable beacons, enabling encrypted communication with command-and-control (C2) servers. The PowerShell loader decompresses executable payloads, facilitating the execution of malicious code on compromised systems. This technique is observed in various attack scenarios, including scripted web delivery, where attackers leverage PowerShell to download and execute malicious payloads directly from web servers. Defenders should prioritize detecting this pattern to identify and prevent Cobalt Strike infections early in the attack chain.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access through various means, such as exploiting web application vulnerabilities or using social engineering to trick users into clicking malicious links.
2.  **Web Delivery:** A user clicks a link, leading to the download of a malicious file or script.
3.  **PowerShell Execution:** The downloaded file, often a script, executes PowerShell.
4.  **Loader Invocation:** The PowerShell script contains the Cobalt Strike PowerShell loader code, designed to decompress and execute the embedded payload.
5.  **Decompression:** The PowerShell loader utilizes `IO.Compression.GzipStream` to decompress a Gzip-compressed executable payload.
6.  **Payload Execution:** After decompression, the payload is executed in memory using `IEX` (Invoke-Expression).
7.  **Beacon Deployment:** The executed payload deploys a Cobalt Strike Beacon, establishing a connection with the C2 server.
8.  **Command and Control:** The attacker gains remote access to the compromised system and can perform various actions, such as data exfiltration, lateral movement, or deploying ransomware.

## Impact

Successful exploitation can lead to complete system compromise, allowing attackers to steal sensitive data, deploy ransomware, or use the compromised system as a foothold for further attacks within the network. Cobalt Strike's flexibility and stealth make it a potent tool for advanced persistent threats (APTs) and ransomware operators, potentially impacting organizations across various sectors. Early detection of the PowerShell loader can prevent significant damage.

## Recommendation

*   Enable PowerShell Script Block Logging (Event ID 4104) to capture the necessary data for detecting the Cobalt Strike PowerShell loader pattern.
*   Deploy the provided Sigma rule (`Cobalt Strike PowerShell Loader`) to your SIEM to identify PowerShell scripts containing the GzipStream decompression pattern.
*   Review and whitelist legitimate penetration testing activities and authorized red team exercises to reduce false positives, as detailed in the `known_false_positives` section.
*   Investigate systems where the Sigma rule triggers to determine the origin of the malicious PowerShell script and contain the potential breach.
