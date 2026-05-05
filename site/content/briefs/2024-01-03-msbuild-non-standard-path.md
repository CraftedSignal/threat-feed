---
title: Suspicious MSBuild Execution from Non-Standard Path
slug: 2024-01-03-msbuild-non-standard-path
description: Detection of msbuild.exe execution from a non-standard path, indicating potential attempts to evade detection and execute malicious code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - msbuild
  - lolbas
  - living-off-the-land
  - defense-evasion
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md
rules:
  - title: Suspicious MSBuild Execution from Non-Standard Path
    description: Detects the execution of msbuild.exe from a non-standard path, indicating potential attempts to evade detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: MSBuild Project File Download via Uncommon Process
    description: Detects the download of .csproj files using uncommon processes, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1105
    data_sources:
      - network_connection
      - windows
  - title: MSBuild Execution Spawning Suspicious Child Process
    description: Detects msbuild.exe spawning suspicious child processes (e.g., cmd.exe, powershell.exe), suggesting potential code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers commonly abuse msbuild.exe, a legitimate Microsoft build tool, to execute malicious code while bypassing security controls. This technique, known as "Living off the Land," allows threat actors to utilize trusted system binaries to perform malicious actions. This analytic focuses on detecting instances where msbuild.exe is executed from a non-standard path. This deviation from the expected execution path is a strong indicator of malicious activity, as legitimate uses typically involve the standard installation directory. Identifying and responding to these anomalous executions can prevent attackers from gaining a foothold and escalating their attacks. This detection is relevant across various attack scenarios, including malware deployment, privilege escalation, and lateral movement.

## Attack Chain

1.  Initial Access: An attacker gains initial access through various methods (e.g., phishing, exploiting a vulnerability).
2.  File Dropping: A malicious payload or script is dropped onto the system.
3.  MSBuild Download: Attacker downloads a malicious .csproj file or modifies an existing one.
4.  Evade defenses: The attacker copies msbuild.exe to a non-standard path.
5.  Execution: The attacker executes msbuild.exe from the non-standard path, pointing it to the malicious .csproj file.
6.  Code Execution: MSBuild parses the project file and executes the embedded malicious code or commands.
7.  Persistence/Lateral Movement: Depending on the executed code, the attacker establishes persistence or moves laterally within the network.
8.  Objective Achieved: The attacker achieves their objective, such as data theft, system compromise, or ransomware deployment.

## Impact

Successful exploitation can lead to arbitrary code execution, system compromise, data exfiltration, and further malicious activities. The execution of msbuild.exe from a non-standard path is often a precursor to more serious attacks, including ransomware deployment.

## Recommendation

*   Implement the Sigma rule "Suspicious MSBuild Execution from Non-Standard Path" to detect msbuild.exe execution from unusual locations based on process creation logs.
*   Enable process creation logging with command-line arguments via Sysmon or other EDR solutions to ensure accurate detection of msbuild.exe execution.
*   Investigate any alerts triggered by the Sigma rule, focusing on the parent process, command-line arguments, and destination IP addresses.
*   Baseline MSBuild.exe usage within your environment to identify legitimate uses and filter them from the detection logic.
*   Monitor for network connections originating from msbuild.exe processes launched from non-standard paths to identify potential command and control activity.
