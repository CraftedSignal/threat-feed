---
title: Ingress Transfer via Windows BITS
slug: 2024-01-bits-ingress-transfer
description: Adversaries may leverage Windows Background Intelligent Transfer Service (BITS) to download executable and archive files to evade defenses and establish command and control.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - bits
  - ingress-transfer
  - command-and-control
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Adobe
  - Docker
products:
  - Background Intelligent Transfer Service (BITS)
  - Adobe Reader
  - Docker Desktop
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1197
    technique_name: BITS Jobs
references:
  - https://attack.mitre.org/techniques/T1197/
rules:
  - title: Detect Ingress Transfer via Windows BITS File Rename
    description: Detects file rename events where svchost.exe renames temporary BITS files to executable or archive file types.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1105
      - T1197
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious File Extension after BITS Rename
    description: Detects suspicious file extensions after a rename operation by svchost.exe from a temporary BITS file.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1105
      - T1197
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Windows Background Intelligent Transfer Service (BITS) is a legitimate Windows service that allows for prioritized, asynchronous, and throttled transfer of files between a client and a server. Adversaries abuse BITS to download malicious payloads while evading typical security protections, as file transfers occur in the context of the `svchost.exe` process. This activity can obscure the origin of the download and bypass application whitelisting rules. This detection focuses on identifying file rename events where `svchost.exe` renames temporary BITS files (BIT*.tmp) to executable or archive file types, indicating a potential malicious download via BITS. This technique is commonly employed to deliver malware, exfiltrate data, or download additional tools.

## Attack Chain

1. An attacker gains initial access to a system (e.g., through phishing or exploiting a vulnerability).
2. The attacker uses a script or command-line interface (e.g., PowerShell) to create a BITS job.
3. The BITS job is configured to download a malicious executable or archive from a remote server using the `bitsadmin.exe` utility.
4. BITS downloads the file to a temporary location on the system with a `BIT*.tmp` extension.
5. The `svchost.exe` process renames the temporary file to its final name and extension (e.g., .exe, .zip).
6. The attacker executes the downloaded file, initiating further malicious activities.
7. The malware establishes persistence through registry keys or scheduled tasks.
8. The malware communicates with a command and control (C2) server to receive instructions and exfiltrate data.

## Impact

Successful exploitation enables attackers to download and execute arbitrary code on compromised systems. The use of BITS can bypass traditional security measures, leading to malware infections, data theft, and potentially full system compromise. This technique can be used in conjunction with other attack vectors to establish a persistent foothold within the network. While the rule itself triggers at low severity, the identified activity can be an early warning of more severe attack stages.

## Recommendation

*   Deploy the "Ingress Transfer via Windows BITS" Sigma rule to your SIEM and tune for your environment.
*   Enable Sysmon file creation and process creation logging to enhance visibility into BITS-related activities.
*   Monitor network connections initiated by `svchost.exe` to identify potentially malicious downloads.
*   Investigate any instances of `bitsadmin.exe` being executed, especially with command-line arguments indicative of suspicious downloads.
*   Review `Microsoft-Windows-Bits-Client/Operational` Windows logs (event ID 59) for unusual BITS events.
*   Block known malicious domains or IP addresses associated with BITS-related attacks at the firewall or DNS resolver.
