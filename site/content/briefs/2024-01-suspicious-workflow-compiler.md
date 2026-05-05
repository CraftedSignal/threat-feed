---
title: Suspicious Microsoft Workflow Compiler Usage
slug: 2024-01-suspicious-workflow-compiler
description: The use of Microsoft Workflow Compiler (microsoft.workflow.compiler.exe), a rarely utilized executable typically found in C:\Windows\Microsoft.NET\Framework64\v4.0.30319, can indicate malicious intent such as code execution or persistence mechanisms, potentially leading to unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - proxy-execution
  - endpoint
vendors:
  - Microsoft
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
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-6---microsoftworkflowcompilerexe-payload-execution
rules:
  - title: Suspicious Microsoft Workflow Compiler Execution
    description: Detects the execution of microsoft.workflow.compiler.exe with unusual parent processes, potentially indicating malicious use.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Microsoft Workflow Compiler with Suspicious Command Line
    description: Detects suspicious command-line arguments used with microsoft.workflow.compiler.exe, such as specifying an output file in a world-writable directory.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft Workflow Compiler (microsoft.workflow.compiler.exe) is a legitimate Microsoft executable, but its usage is uncommon in typical environments. This makes it an attractive target for attackers looking to bypass security controls and execute malicious code. Located in C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319, the executable is designed for compiling workflow definitions, but can be abused to execute arbitrary code. Its rare usage means that any execution of this binary warrants further investigation. This activity is often seen after initial compromise, as an attempt to establish persistence or execute payloads.

## Attack Chain

1. An attacker gains initial access to the system, potentially through exploitation of a vulnerability or social engineering.
2. The attacker leverages an existing scripting capability (e.g., PowerShell) to stage the malicious payload.
3. The attacker executes microsoft.workflow.compiler.exe to compile and execute a malicious workflow definition.
4. The workflow definition contains embedded code or calls out to external resources to download and execute additional payloads.
5. The compiled code executes in the context of the workflow compiler process, potentially bypassing application whitelisting.
6. The attacker establishes persistence by creating a scheduled task or modifying registry keys to automatically execute the malicious workflow on system startup.
7. The attacker performs lateral movement using the compromised system as a pivot point to access other systems within the network.

## Impact

Successful exploitation can allow attackers to execute arbitrary code, bypass application whitelisting, and establish persistence on compromised systems. The lack of widespread usage of the Microsoft Workflow Compiler makes its malicious use difficult to detect, potentially allowing attackers to maintain a foothold in the environment for extended periods. If the attacker achieves persistence and lateral movement, it could lead to data exfiltration, ransomware deployment, or other significant security incidents.

## Recommendation

*   Deploy the Sigma rule `Suspicious Microsoft Workflow Compiler Execution` to detect the execution of `microsoft.workflow.compiler.exe` with unusual parent processes.
*   Enable Sysmon process creation logging (Event ID 1) or Windows Event Log Security (4688) to ensure the necessary telemetry for the detection is available.
*   Investigate any identified instances of `microsoft.workflow.compiler.exe` execution, paying close attention to the parent process, command-line arguments, and network activity.
*   Monitor process execution data for unusual parent-child process relationships involving `microsoft.workflow.compiler.exe`, especially if the parent process is a scripting engine like PowerShell or cmd.exe.
*   Review and tune the `suspicious_microsoft_workflow_compiler_usage_filter` macro in the original Splunk search to reduce false positives in your environment.
