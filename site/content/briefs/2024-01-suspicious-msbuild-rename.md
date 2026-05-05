---
title: Suspicious MSBuild Rename
slug: 2024-01-suspicious-msbuild-rename
description: The analytic detects the execution of renamed instances of msbuild.exe, a legitimate tool abused by attackers to execute malicious code while evading detection, potentially leading to system compromise, data exfiltration, or lateral movement.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lolbin
  - msbuild
  - defense-evasion
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md
  - https://github.com/infosecn1nja/MaliciousMacroMSBuild/
rules:
  - title: Suspicious MSBuild Rename
    description: Detects the execution of renamed MSBuild.exe instances
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036.003
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: MSBuild Spawned Suspicious Child Processes
    description: Detects MSBuild spawning command interpreters or script hosts
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies renamed instances of `msbuild.exe` being executed. `msbuild.exe` is a legitimate Microsoft build tool, but attackers frequently abuse it to proxy execution of malicious code, bypassing application control and other security measures. This is a living-off-the-land technique (LOLBAS) that allows adversaries to execute arbitrary code without introducing new, potentially detectable binaries to the system. Successful exploitation can lead to system compromise, data exfiltration, or further lateral movement. The LOLBAS Project and Atomic Red Team provide further context around MSBuild's abuse potential. This technique has been associated with various threat actors and ransomware families, including Cobalt Strike, BlackByte Ransomware, and the Storm-2460 CLFS Zero Day Exploitation.

## Attack Chain

1.  The attacker gains initial access via an existing vulnerability or remote access mechanism (not detailed in source).
2.  The attacker renames `msbuild.exe` to a different filename (e.g., `msbuild_renamed.exe`).
3.  The attacker crafts a malicious XML project file containing inline code or instructions to download and execute a payload.
4.  The attacker executes the renamed `msbuild.exe` with the malicious project file as an argument (`msbuild_renamed.exe evil.xml`).
5.  `msbuild.exe` parses the XML file and executes the embedded malicious code. This code could be shellcode, PowerShell commands, or .NET assemblies.
6.  The executed code performs malicious actions, such as downloading additional malware, establishing persistence, or exfiltrating data.
7.  The attacker uses the compromised system to move laterally within the network, escalating privileges and accessing sensitive resources.

## Impact

Successful execution of renamed `msbuild.exe` can lead to full system compromise. Attackers can leverage this technique to bypass application control and execute arbitrary code, potentially leading to data theft, ransomware deployment, or disruption of critical services. The use of a trusted system utility for malicious purposes makes detection more challenging, increasing the likelihood of successful exploitation.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) and Windows Event Log Security 4688 to capture process execution details.
*   Deploy the Sigma rule `Suspicious MSBuild Rename` to your SIEM to detect renamed instances of `msbuild.exe`.
*   Investigate any instances of renamed `msbuild.exe` executions, focusing on the parent processes, command-line arguments, and network connections.
*   Implement application control policies to restrict the execution of renamed system utilities.
*   Monitor for unusual network activity originating from systems where `msbuild.exe` has been renamed.
