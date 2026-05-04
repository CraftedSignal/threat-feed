---
title: Remote Execution of Windows Services via RPC
slug: 2024-01-remote-service-execution
description: Detection of remote execution of Windows services over RPC by correlating `services.exe` network connections and spawned child processes, potentially indicating lateral movement.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - execution
  - windows
vendors:
  - Microsoft
  - Pella Corporation
  - AdminArsenal
  - ESET
  - Veeam
products:
  - SCCM
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_remote_services.toml
rules:
  - title: Remotely Started Services via RPC - Process Creation
    description: Detects processes started by services.exe after a network connection, indicating potential remote service execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021
      - T1569.002
    data_sources:
      - process_creation
      - windows
  - title: Remotely Started Services via RPC - Network Connection
    description: Detects incoming network connections to services.exe on high ports, indicative of RPC activity.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection rule identifies the remote execution of Windows services over Remote Procedure Call (RPC), a technique often employed for lateral movement within a network. The rule focuses on correlating network connections initiated by `services.exe` with subsequent child process creation events. While this activity can be a legitimate function of administrators using remote management tools, it also represents a potential attack vector. The rule aims to strike a balance between detecting malicious activity and minimizing false positives arising from routine administrative tasks. The detection logic is based on identifying network connections to `services.exe` followed by the creation of child processes that are not commonly associated with legitimate service management. The rule requires the use of Elastic Defend or Sysmon for adequate logging coverage.

## Attack Chain

1.  An attacker gains initial access to a system within the network.
2.  The attacker attempts to move laterally to other systems.
3.  The attacker establishes a connection to the target system's `services.exe` process over RPC using a high port (>= 49152).
4.  The attacker uses the established RPC connection to create or start a new service on the remote system.
5.  The `services.exe` process on the remote system spawns a child process related to the newly created or started service.
6.  This new process executes the attacker's payload, potentially granting further access or executing malicious commands.
7.  The attacker leverages the newly executed service for persistent access or further lateral movement.

## Impact

A successful attack could result in unauthorized access to sensitive data, disruption of critical services, or the deployment of ransomware. Lateral movement allows attackers to compromise multiple systems within the network, escalating the impact of the initial breach. Due to the nature of the technique, it can be challenging to distinguish between legitimate administrative activity and malicious actions, leading to delayed detection and increased dwell time for attackers.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune the filters for known-good executables in your environment to reduce false positives.
*   Enable Sysmon process-creation (Event ID 1) and network connection (Event ID 3) logging to ensure the required data for the Sigma rules is available.
*   Investigate any alerts triggered by these rules, focusing on the parent process and network connection details associated with the spawned child process.
*   Consider excluding known remote management tools from triggering the detection by adding exceptions based on `process.executable` or `process.args` in the Sigma rules.
*   Monitor the network for unusual RPC activity, especially connections to `services.exe` from unexpected source IPs.
