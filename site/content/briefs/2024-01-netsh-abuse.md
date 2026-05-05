---
title: Detection of Processes Launching netsh.exe for Malicious Purposes
slug: 2024-01-netsh-abuse
description: Detection of netsh.exe execution by unusual processes indicative of potential malicious activity, including persistence and network configuration changes by threat actors.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - netsh
  - living-off-the-land
  - persistence
  - network-configuration
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows
references:
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
rules:
  - title: Detect Suspicious Processes Launching Netsh
    description: Detects unusual processes launching netsh.exe, which may indicate malicious activity such as persistence or network configuration changes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Netsh Helper DLL Load
    description: Detects netsh.exe loading a helper DLL, often used for malicious persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This brief focuses on the anomalous execution of `netsh.exe`, a command-line utility native to Windows operating systems used for network configuration. While legitimate use of `netsh.exe` exists, its invocation by uncommon processes can signify malicious activity, such as establishing persistence or modifying network settings. This activity has been observed in attacks attributed to Volt Typhoon, where it was used for "living off the land" tactics targeting US critical infrastructure, and in malware campaigns involving Azorult, Snake Keylogger, ShrinkLocker, and Hellcat Ransomware. Defenders should monitor for unexpected processes launching `netsh.exe` to identify potential threats within their environments.

## Attack Chain

1.  An attacker gains initial access to a system through various means (e.g., compromised credentials, exploitation of vulnerabilities).
2.  The attacker attempts to establish persistence on the compromised system.
3.  The attacker uses a process (e.g., a script interpreter or legitimate application) to execute `netsh.exe`.
4.  `netsh.exe` is invoked with specific commands to modify network configurations (e.g., adding firewall rules, configuring port forwarding, or changing DNS settings).
5.  These network configuration changes facilitate further malicious activities, such as lateral movement, command and control communication, or data exfiltration.
6.  Malicious helper DLLs are loaded through `netsh.exe` to maintain persistent access.
7.  The attacker uses the compromised system as a foothold to move laterally within the network, targeting critical assets.
8.  The attacker achieves their objective, such as data theft, system disruption, or ransomware deployment.

## Impact

Successful exploitation via anomalous `netsh.exe` execution can lead to significant network compromise, including persistent access for attackers, unauthorized modification of network settings, and potential privilege escalation. This can result in data breaches, service disruption, and reputational damage. The Volt Typhoon campaign targeted US critical infrastructure, demonstrating the potential for significant impact on national security. Multiple malware families including Azorult, Snake Keylogger, ShrinkLocker, and Hellcat Ransomware have been known to abuse `netsh.exe`.

## Recommendation

*   Monitor process creation events (Sysmon Event ID 1, Windows Event Log Security 4688) for the execution of `netsh.exe` by unusual parent processes.
*   Implement the Sigma rule `Detect Suspicious Processes Launching Netsh` to identify suspicious invocations of `netsh.exe`.
*   Investigate any instances where `netsh.exe` is launched with network configuration-related commands.
*   Review and audit existing `netsh.exe` configurations to identify any unauthorized or malicious changes.
*   Consider blocking execution of `netsh.exe` where it is not required for legitimate business operations.
*   Deploy the Sigma rule `Detect Netsh Helper DLL Load` to detect malicious DLL loading by netsh.exe.
