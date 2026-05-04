---
title: Suspicious .NET Code Compilation via Unusual Parent Processes
slug: 2024-01-02-suspicious-dotnet-compilation
description: Adversaries may use unusual parent processes to execute .NET compilers for compiling malicious code after delivery, evading security mechanisms, and this activity is detected by monitoring compiler executions initiated by scripting engines or system utilities.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - compile-after-delivery
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_dotnet_compiler_parent_process.toml
  - https://attack.mitre.org/techniques/T1027/004/
rules:
  - title: Suspicious .NET Code Compilation
    description: Detects executions of .NET compilers with suspicious parent processes, indicating potential evasion or execution tactics.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.004
    data_sources:
      - process_creation
      - windows
  - title: Suspicious .NET Compiler Command Line Arguments
    description: Detects command line arguments commonly associated with malicious use of .NET compilers, such as specifying an output path in a public directory.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers sometimes deliver malicious code in a non-executable format to bypass initial security checks. They then use legitimate .NET compilers like `csc.exe` (C#) and `vbc.exe` (VB.NET) to compile the code into an executable on the victim machine. This technique, known as "Compile After Delivery", helps them evade traditional signature-based detections. This activity is often launched from scripting engines or system utilities, such as `wscript.exe`, `mshta.exe`, `cmstp.exe`, `regsvr32.exe` and others. The rule detects these unusual parent-child process relationships, providing an alert for potential post-delivery code compilation activity, and applies to Windows environments.

## Attack Chain

1. An attacker gains initial access via an unspecified method.
2. The attacker delivers obfuscated or encoded .NET source code to the target system.
3. The attacker uses a scripting engine (e.g., `wscript.exe`, `mshta.exe`, `cscript.exe`) or system utility (e.g., `wmic.exe`, `regsvr32.exe`, `cmstp.exe`) to execute a .NET compiler (`csc.exe` or `vbc.exe`).
4. The scripting engine or system utility passes the delivered .NET source code as an argument to the compiler.
5. The .NET compiler compiles the source code into a binary executable.
6. The attacker executes the compiled binary.
7. The compiled binary performs malicious actions, such as establishing persistence, lateral movement, or data exfiltration.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the target system, bypassing security measures that rely on pre-execution scanning. This can lead to a range of malicious activities, including data theft, system compromise, and deployment of ransomware. Detecting and preventing this technique is crucial for maintaining the integrity and confidentiality of systems.

## Recommendation

*   Enable process creation logging via Windows Security Event Logs or Sysmon (Event ID 1) to capture process execution data needed for the detection rule.
*   Deploy the Sigma rule "Suspicious .NET Code Compilation" to your SIEM to detect instances of .NET compilers being executed by unusual parent processes.
*   Implement application whitelisting to prevent unauthorized execution of compilers and scripting engines by non-standard parent processes, as described in the rule's documentation.
*   Monitor process execution for the parent processes listed in the Sigma rule's detection criteria (e.g., `wscript.exe`, `mshta.exe`, `cmstp.exe`, `regsvr32.exe`) for unusual command-line arguments.
