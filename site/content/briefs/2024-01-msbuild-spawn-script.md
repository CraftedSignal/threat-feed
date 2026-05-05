---
title: MSBuild Executed by Scripting Host
slug: 2024-01-msbuild-spawn-script
description: Detects the suspicious spawning of MSBuild.exe by Windows Script Host processes (cscript.exe or wscript.exe), a behavior often associated with malware executing malicious MSBuild processes via scripts.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - msbuild
  - scripting
  - defense-evasion
  - endpoint
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
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
references:
  - https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/msbuild_suspicious_spawned_by_script_process.yml
rules:
  - title: MSBuild Spawned by Scripting Host
    description: Detects MSBuild.exe spawned by scripting hosts like wscript.exe or cscript.exe.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: MSBuild Child Processes
    description: Detects MSBuild spawning suspicious child processes
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief addresses the threat of malicious use of MSBuild.exe, a legitimate Microsoft build tool, by adversaries through scripting hosts like cscript.exe and wscript.exe. Attackers leverage this technique to bypass application control and execute arbitrary code. This activity is significant as it indicates an attempt to execute malicious code, leading to unauthorized code execution and potentially compromising the host. This technique is often associated with malware or adversaries executing malicious MSBuild processes via scripts on compromised hosts. The detection focuses on process creation events where MSBuild is a child of script hosts.

## Attack Chain

1.  An attacker gains initial access via an undisclosed method.
2.  The attacker deploys a malicious script (e.g., VBScript, JScript) on the target system.
3.  The script is executed using Windows Script Host (cscript.exe or wscript.exe).
4.  The script spawns MSBuild.exe, often with command-line arguments that specify a malicious project file.
5.  MSBuild.exe loads and executes the malicious project file.
6.  The project file contains tasks designed to execute arbitrary code, download additional payloads, or perform other malicious activities.
7.  The executed code establishes persistence.
8.  The adversary achieves their objective, such as data exfiltration or lateral movement.

## Impact

Successful exploitation can lead to unauthorized code execution, potentially compromising the host and allowing further malicious activities such as data theft, system compromise, or deployment of ransomware. While the number of victims and specific sectors are not specified, the potential impact is significant due to the widespread use of MSBuild and Windows Script Host in enterprise environments.

## Recommendation

*   Deploy the Sigma rule `MSBuild Spawned by Scripting Host` to your SIEM to identify suspicious MSBuild executions originating from scripting hosts.
*   Enable process creation logging (Event ID 4688 or Sysmon Event ID 1) to capture the necessary process relationships for the detection.
*   Implement application control policies to restrict the execution of unsigned or untrusted MSBuild project files.
*   Monitor parent-child process relationships for unusual executions of MSBuild.exe (e.g., spawned by scripting hosts) using EDR telemetry.
*   Review and audit any scripts executing MSBuild.exe within the environment to identify potential malicious activity.
