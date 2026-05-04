---
title: Suspicious SolarWinds Child Process Execution
slug: 2024-01-solarwinds-child-process
description: Detection of unusual child processes spawned by SolarWinds processes may indicate malicious program execution, potentially bypassing security controls.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - supply-chain
  - execution
  - solarwinds
vendors:
  - Elastic
  - SolarWinds
  - SentinelOne
products:
  - Elastic Defend
  - SolarWinds.BusinessLayerHost.exe
  - SolarWinds.BusinessLayerHostx64.exe
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
  - https://github.com/mandiant/sunburst_countermeasures/blob/main/rules/SUNBURST/hxioc/SUNBURST%20SUSPICIOUS%20CHILD%20PROCESSES%20(METHODOLOGY).ioc
rules:
  - title: Suspicious SolarWinds Child Process - CommandLine
    description: Detects suspicious command lines in child processes of SolarWinds BusinessLayerHost.exe
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1195.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious SolarWinds Child Process - Executable
    description: Detects suspicious executable names in child processes of SolarWinds BusinessLayerHost.exe
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies suspicious child processes initiated by SolarWinds.BusinessLayerHost.exe or SolarWinds.BusinessLayerHostx64.exe, excluding known legitimate operations. Adversaries may exploit the trusted SolarWinds processes to execute unauthorized programs with elevated privileges, bypassing security controls. The rule focuses on Windows systems and is designed to detect activity indicative of post-compromise actions following a supply chain attack. This detection is crucial for organizations that utilize SolarWinds software, as malicious actors could leverage compromised SolarWinds installations to gain unauthorized access and execute arbitrary code within the network.

## Attack Chain

1. Initial compromise of the SolarWinds software supply chain (T1195.002).
2. Malicious code is injected into SolarWinds.BusinessLayerHost.exe or SolarWinds.BusinessLayerHostx64.exe.
3. The compromised SolarWinds process spawns a suspicious child process.
4. The child process executes a malicious command or binary, attempting to evade detection.
5. The child process leverages Native APIs (T1106) to perform privileged actions.
6. Lateral movement or data exfiltration may occur from the compromised host.

## Impact

A successful attack can lead to the execution of arbitrary code on systems running SolarWinds software. This can result in data theft, system compromise, and further propagation of the attack throughout the network. Organizations in various sectors utilizing SolarWinds products are potentially at risk. The impact may include loss of sensitive data, disruption of critical services, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Suspicious SolarWinds Child Process - CommandLine` to detect potentially malicious child processes of SolarWinds.BusinessLayerHost.exe or SolarWinds.BusinessLayerHostx64.exe.
*   Deploy the Sigma rule `Suspicious SolarWinds Child Process - Executable` to detect execution of unusual executables as child processes of SolarWinds.BusinessLayerHost.exe or SolarWinds.BusinessLayerHostx64.exe.
*   Enable process creation logging with command line details on Windows systems to ensure the Sigma rules have sufficient data.
*   Review and tune the rules for false positives based on legitimate SolarWinds child processes in your environment, updating the exclusion lists in the rules accordingly, referencing the "false_positives" section in the rule description.
