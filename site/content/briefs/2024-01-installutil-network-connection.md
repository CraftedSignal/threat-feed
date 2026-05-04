---
title: InstallUtil Process Making Network Connections for Defense Evasion
slug: 2024-01-installutil-network-connection
description: Detection of InstallUtil.exe making outbound network connections, which can indicate adversaries leveraging it to execute code and evade detection by proxying execution through a trusted system binary.
date: "2024-01-03T18:15:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - proxy-execution
  - windows
vendors:
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/004/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_installutil_beacon.toml
rules:
  - title: InstallUtil Network Connection
    description: Detects InstallUtil.exe making outbound network connections, which can indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.004
    data_sources:
      - network_connection
      - windows
  - title: InstallUtil Process Creation
    description: Detects InstallUtil.exe process creation, useful for baselining and correlation with network events.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1218.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

InstallUtil.exe is a legitimate Windows utility used for installing and uninstalling server resources. Adversaries abuse InstallUtil.exe to execute malicious code under the guise of legitimate processes, often to evade detection. This technique allows attackers to proxy execution through a trusted system binary, potentially bypassing application control and security monitoring. The detection rule identifies suspicious network activity by monitoring InstallUtil.exe's outbound connections, flagging potential misuse by alerting on the initial network connection attempt. This activity is detected via the Elastic EQL rule "InstallUtil Process Making Network Connections."

## Attack Chain

1. An attacker gains initial access through an undisclosed method.
2. The attacker uses InstallUtil.exe to execute a malicious .NET assembly.
3. InstallUtil.exe loads the malicious assembly into its process.
4. The malicious assembly executes code that establishes an outbound network connection.
5. The connection is used for command and control (C2) or data exfiltration.
6. The attacker may use the C2 channel to download and execute further payloads.
7. The attacker performs lateral movement within the network.
8. The attacker achieves their objective, such as data theft or system compromise.

## Impact

Successful exploitation can lead to arbitrary code execution within the context of a trusted Windows process (InstallUtil.exe), bypassing application control and potentially evading detection. This could result in a compromised system, data exfiltration, or further malicious activities within the network. The scope of impact depends on the attacker's objectives and the level of access gained, potentially affecting entire organizations.

## Recommendation

*   Enable process creation logging and network connection logging via Sysmon or Elastic Defend to provide the data needed for the rules below.
*   Deploy the Sigma rule "InstallUtil Network Connection" to your SIEM and tune for your environment to detect suspicious outbound network connections from InstallUtil.exe.
*   Investigate any alerts triggered by the Sigma rule by examining the parent process of InstallUtil.exe, destination IP addresses, and associated activities.
*   Implement network monitoring and alerting for unusual outbound connections from critical systems to enhance detection of similar threats in the future.
