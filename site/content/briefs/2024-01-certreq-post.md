---
title: Certreq HTTP POST Abuse for File Transfer
slug: 2024-01-certreq-post
description: Adversaries may abuse the Windows Certreq utility to download files or upload data to a remote URL by making an HTTP POST request, potentially for command and control, defense evasion, or exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lolbin
  - certreq
  - command-and-control
  - defense-evasion
  - exfiltration
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Certreq/
rules:
  - title: Detect Certreq HTTP POST Request
    description: Detects the execution of certreq.exe with the -Post argument, which can be used for file transfer or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1071.001
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Certreq Network Connection
    description: Detects network connections made by certreq.exe which is an indication of potential malicious activity.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1071.001
      - T1218
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Windows Certreq utility is a command-line tool used for certificate requests and management. However, it can be abused by attackers to download files or upload data to remote URLs using HTTP POST requests. This technique can be employed for various malicious purposes, including command and control, defense evasion, and exfiltration. This activity is typically seen following an initial compromise, where Certreq is used as a Living-off-the-Land Binary (LOLBin) to avoid detection and blend in with legitimate system activity. The abuse of Certreq.exe with the `-Post` argument is a red flag that warrants investigation.

## Attack Chain

1. An attacker gains initial access to a Windows system through a vulnerability or compromised credentials.
2. The attacker executes `certreq.exe` with the `-Post` argument to initiate an HTTP POST request.
3. The `certreq.exe` command is used to download a malicious payload from a remote server.
4. The downloaded payload is saved to disk, potentially bypassing some endpoint detection systems due to the use of a legitimate system binary.
5. The attacker executes the downloaded payload, establishing a reverse shell or performing other malicious activities.
6. The attacker uses the same `certreq.exe -Post` technique to upload collected data to a command and control server.
7. The attacker leverages the established C2 channel to move laterally within the network.
8. The attacker exfiltrates sensitive data using `certreq.exe -Post` over web protocols to an external server.

## Impact

Successful exploitation can lead to the compromise of sensitive data, the establishment of persistent backdoors, and further propagation within the network. The use of a legitimate system binary like `certreq.exe` makes detection more challenging, allowing attackers to operate undetected for extended periods. While the specific number of victims is unknown, organizations that do not monitor for LOLBin abuse are at higher risk.

## Recommendation

*   Deploy the Sigma rule "Detect Certreq HTTP POST Request" to detect the execution of `certreq.exe` with the `-Post` argument (see below).
*   Monitor process creation events for the execution of `certreq.exe`, focusing on command-line arguments and parent processes.
*   Implement network monitoring to detect suspicious outbound HTTP POST requests originating from `certreq.exe`.
*   Investigate any instances of `certreq.exe` making network connections to unusual or suspicious domains.
*   Enable Windows Security Event Logging and Sysmon to capture detailed process execution and network connection information.
