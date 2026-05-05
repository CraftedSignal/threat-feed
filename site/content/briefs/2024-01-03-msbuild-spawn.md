---
title: Suspicious MSBuild Spawned by WMI Provider Process
slug: 2024-01-03-msbuild-spawn
description: The analytic identifies instances where wmiprvse.exe spawns msbuild.exe, an unusual process relationship indicative of potential COM object misuse and unauthorized code execution on Windows systems.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - defense-evasion
  - msbuild
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md
rules:
  - title: Suspicious MSBuild Spawned by WMI Provider
    description: Detects instances where wmiprvse.exe spawns msbuild.exe, which is unusual and potentially malicious.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: MSBuild Executes Suspicious Command-Line Arguments
    description: Detects MSBuild executing with command-line arguments indicative of malicious activity, such as inline task execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a suspicious process execution pattern where `wmiprvse.exe` (the WMI Provider Host process) spawns `msbuild.exe`. This behavior is atypical because `msbuild.exe` is usually initiated by `devenv.exe` (Visual Studio) during software development. An adversary might leverage this technique to proxy execution of malicious code through a trusted Windows utility, a tactic known as "Living off the Land." The activity is significant because it allows attackers to execute arbitrary code or scripts without directly introducing new executables, potentially leading to system compromise or further malicious activities, such as lateral movement and data exfiltration. The detection focuses on process relationships and command-line executions observed on Windows endpoints. This technique has been observed in campaigns such as the Storm-2460 CLFS Zero Day Exploitation.

## Attack Chain

1.  The attacker gains initial access to the system through an exploit or compromised credentials.
2.  The attacker uses WMI to execute a malicious command or script.
3.  `wmiprvse.exe` is invoked as part of the WMI execution process.
4.  The attacker crafts a malicious project file or uses an existing one to execute code through MSBuild.
5.  `wmiprvse.exe` spawns `msbuild.exe` to build and execute the malicious project.
6.  `msbuild.exe` executes the attacker's code, potentially downloading additional payloads or executing commands.
7.  The attacker achieves code execution within the context of MSBuild, bypassing some application control defenses.
8.  The attacker performs further malicious activities such as credential theft, lateral movement, or data exfiltration.

## Impact

Successful exploitation allows attackers to execute arbitrary code, escalate privileges, and bypass application control mechanisms. This can lead to full system compromise, data theft, and further propagation within the network. The number of affected systems depends on the scope of the initial compromise. Successful attacks leveraging this technique have been observed to facilitate lateral movement and data exfiltration.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) to capture process relationships for detection.
*   Deploy the Sigma rule `Suspicious MSBuild Spawned by WMI Provider` to your SIEM to detect anomalous process spawns.
*   Investigate any instances where `wmiprvse.exe` spawns `msbuild.exe`, focusing on the executed command-line arguments and project files.
*   Implement application control policies to restrict the execution of `msbuild.exe` to authorized users and processes.
*   Monitor for suspicious network connections originating from `msbuild.exe` processes using a network intrusion detection system (NIDS).
