---
title: Suspicious .NET Code Compilation via Unusual Parent Processes
slug: 2024-01-dotnet-compiler-parent
description: The execution of .NET compilers (csc.exe, vbc.exe) with suspicious parent processes (wscript.exe, mshta.exe, etc.) indicates potential attempts to compile code after delivery for defense evasion and execution.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - dotnet
  - compiler
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://attack.mitre.org/techniques/T1027/
  - https://attack.mitre.org/techniques/T1027/004/
  - https://attack.mitre.org/techniques/T1127/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/003/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1218/010/
  - https://attack.mitre.org/techniques/T1218/011/
  - https://attack.mitre.org/techniques/T1047/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1059/007/
rules:
  - title: Suspicious .NET Compiler Invocation by Unusual Processes
    description: Detects .NET compilers (csc.exe, vbc.exe) being executed by unusual parent processes, potentially indicating malicious code compilation after delivery.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.004
      - T1127
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Suspicious .NET Compiler Invocation with svchost as Parent
    description: Detects .NET compilers (csc.exe, vbc.exe) being executed by svchost.exe, which is highly unusual and often indicative of malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.004
      - T1127
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to bypass security mechanisms by compiling malicious code on a target system after initial delivery. This is often achieved by leveraging .NET compilers such as csc.exe (C# compiler) and vbc.exe (VB.NET compiler) executed via unusual parent processes. This activity allows attackers to convert human-readable code into executable form, potentially evading signature-based detections. The use of scripting engines and system utilities as parent processes of these compilers can indicate malicious intent, as these are not typical scenarios for legitimate software development. This activity could be part of a broader attack campaign to establish persistence, execute arbitrary code, or perform lateral movement within a network. Defenders should monitor process relationships and command-line arguments for unusual patterns involving .NET compilers.

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2. The attacker delivers obfuscated or encoded .NET source code to the compromised host.
3. A scripting engine or system utility (e.g., wscript.exe, mshta.exe, cmd.exe) is used to initiate the compilation process.
4. The .NET compiler (csc.exe or vbc.exe) is invoked by the suspicious parent process.
5. The compiler reads the delivered .NET source code from a file or command-line arguments.
6. The compiler generates a .NET assembly (DLL or EXE file) containing the compiled code.
7. The compiled assembly is loaded and executed, performing malicious actions such as establishing persistence, downloading additional payloads, or exfiltrating data.
8. The attacker removes or obfuscates the original source code to hinder forensic analysis.

## Impact

Successful exploitation can lead to arbitrary code execution, persistence, and further compromise of the affected system. Attackers can use this technique to bypass application whitelisting or other security controls that rely on static analysis of executable files. This can result in data theft, system disruption, or further propagation of malware within the network. The impact is significant if the compromised system has access to sensitive data or critical infrastructure.

## Recommendation

*   Monitor process creation events for .NET compilers (csc.exe, vbc.exe) with unusual parent processes (wscript.exe, mshta.exe, cscript.exe, wmic.exe, svchost.exe, rundll32.exe, cmstp.exe, regsvr32.exe) using the "Suspicious .NET Code Compilation" rule.
*   Enable Sysmon process creation logging (Event ID 1) to capture process relationships and command-line arguments for accurate detection.
*   Deploy the Sigma rule `Suspicious .NET Compiler Invocation by Unusual Processes` to your SIEM to identify instances of this behavior.
*   Implement application whitelisting to restrict the execution of .NET compilers to authorized processes only.
