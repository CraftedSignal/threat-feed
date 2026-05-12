---
title: Incoming DCOM Lateral Movement via MSHTA
slug: 2026-05-incoming-dcom-mshta
description: Detection of Distributed Component Object Model (DCOM) abuse to execute commands from a remote host via the HTA Application COM Object, potentially indicating lateral movement.
date: "2026-05-12T17:45:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - windows
  - dcom
  - mshta
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_dcom_hta.toml
  - https://code-white.com/blog/2018-07-lethalhta/
rules:
  - title: Detect Incoming DCOM Lateral Movement via MSHTA
    description: Detects mshta.exe being used as a COM server (launched with -Embedding) which is indicative of DCOM lateral movement.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Incoming DCOM Lateral Movement via MSHTA - Network
    description: Detects incoming network connections to mshta.exe on high ports, potentially indicating DCOM lateral movement.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The threat involves the abuse of Distributed Component Object Model (DCOM) to facilitate lateral movement within a Windows environment. Attackers leverage the HTA Application COM Object to execute commands remotely. This technique allows malicious actors to execute code on a target system by exploiting the DCOM protocol, often evading traditional endpoint detection methods. The activity is typically initiated from a remote host, targeting systems within the same network. The use of MSHTA (Microsoft HTML Application Host) in conjunction with DCOM provides a mechanism for executing arbitrary code, potentially leading to further compromise of the network. The elastic github detection rule was updated on 2026/05/03.

## Attack Chain

1. An attacker compromises an initial system within the network.
2. The attacker uses DCOM to remotely invoke the MSHTA application on a target host.
3. MSHTA is launched with the `-Embedding` argument, indicating it is being used as a COM server.
4. The MSHTA process initiates an incoming network connection (TCP) on a high port (above 49151).
5. The MSHTA process retrieves and executes malicious HTML Application (HTA) code, potentially from a remote server.
6. The executed HTA code performs malicious actions, such as downloading additional payloads or executing commands.
7. The attacker achieves code execution on the target system, potentially leading to lateral movement.
8. The attacker pivots to other systems within the network, repeating the process.

## Impact

Successful exploitation can lead to unauthorized code execution, lateral movement within the network, and potential data exfiltration or system compromise. This technique allows attackers to bypass traditional security controls and gain access to sensitive resources. The impact can range from data theft and system disruption to complete network compromise, potentially affecting all Windows-based systems within the targeted environment.

## Recommendation

*   Enable Sysmon process creation logging to detect mshta.exe execution with the `-Embedding` argument (rule: "Detect Incoming DCOM Lateral Movement via MSHTA").
*   Monitor network connections initiated by mshta.exe, specifically looking for incoming TCP connections on high ports (above 49151) from remote hosts (rule: "Detect Incoming DCOM Lateral Movement via MSHTA - Network").
*   Implement the Elastic EQL rule "Incoming DCOM Lateral Movement via MSHTA" provided in the source to detect this activity.
*   Investigate any mshta.exe processes that spawn child processes, especially those that involve command interpreters or other potentially malicious tools (see the attack chain above).
*   Review Windows Security event logs for DCOM activation events to identify potentially malicious activity.
