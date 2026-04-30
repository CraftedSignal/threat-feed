---
title: Service Reconnaissance via WMIC.exe
slug: 2024-01-30-wmic-service-recon
description: Adversaries use WMIC.exe to enumerate running services on remote devices, potentially identifying valuable targets or misconfigured systems.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.execution
  - attack.t1047
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic
  - https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
rules:
  - title: Detect Suspicious WMIC Service Enumeration
    description: Detects the execution of wmic.exe to enumerate services on remote hosts
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
  - title: WMIC Reconnaissance with Specific Service Query
    description: Detects wmic.exe being used to specifically query for a service.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may leverage the Windows Management Instrumentation Command-line (WMIC) tool for reconnaissance activities within a network. Specifically, WMIC can be used to query and retrieve information about services running on remote systems. By executing WMIC commands with the 'service' parameter, adversaries can identify the presence and status of specific services, potentially revealing vulnerable or misconfigured systems. This information can then be used to guide further exploitation attempts. WMIC is a built-in Windows utility, making its activity blend with legitimate system administration tasks, increasing the difficulty of detection. This activity is a component of the broader T1047 technique (Windows Management Instrumentation).

## Attack Chain

1.  The attacker gains initial access to a compromised system within the target network.
2.  The attacker executes WMIC.exe from the command line.
3.  WMIC.exe is invoked with the `service` parameter to query service information.
4.  The command includes a target IP address or hostname to query a remote system.
5.  The command attempts to retrieve service names and status information (e.g., `wmic /node:"192.168.1.100" service get name, state`).
6.  WMIC attempts to connect to the remote host via RPC. An error message is generated if the remote host is unreachable: "Node - (provided IP or default) ERROR Description =The RPC server is unavailable".
7.  If the target service is not running, a "No instance(s) Available" message may be displayed.
8.  The attacker parses the output from WMIC to identify running services of interest for further exploitation or lateral movement.

## Impact

Successful service reconnaissance allows attackers to map potential attack vectors within a network. By identifying specific services running on remote systems, attackers can prioritize targets for exploitation based on known vulnerabilities or misconfigurations. This can lead to unauthorized access, data breaches, and system compromise. While the reconnaissance itself does not directly cause harm, it provides crucial information that enables subsequent malicious activities.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious WMIC Service Enumeration` to your SIEM to identify potential service reconnaissance attempts via WMIC (logsource: process_creation, product: windows).
*   Monitor process creation events for `WMIC.exe` executions containing the `service` parameter using endpoint detection and response (EDR) solutions (logsource: process_creation, product: windows).
*   Implement network segmentation to limit the scope of potential reconnaissance activities.
*   Review and restrict the use of WMIC in your environment, as it is a common tool for both legitimate administration and malicious activity.
