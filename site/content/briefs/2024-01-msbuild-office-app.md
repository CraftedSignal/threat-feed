---
title: MSBuild Started by Microsoft Office Application
slug: 2024-01-msbuild-office-app
description: The Microsoft Build Engine (MSBuild) being started by a Microsoft Office application is an unusual behavior that could indicate a malicious document is executing a payload to evade defenses and execute code.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - execution
  - msbuild
  - office-macro
vendors:
  - Microsoft
products:
  - Word
  - Excel
  - PowerPoint
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html
rules:
  - title: Microsoft Build Engine Started by an Office Application
    description: Detects instances of MSBuild.exe being started by a Microsoft Office application, indicating potential malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1127.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect MSBuild network connection
    description: Detects network connections initiated by MSBuild process
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Attackers are increasingly leveraging trusted developer utilities like MSBuild to proxy the execution of malicious code, effectively bypassing traditional security measures. When MSBuild, a legitimate component of the .NET framework, is spawned by a Microsoft Office application (e.g., Word, Excel, PowerPoint), it is a strong indicator of suspicious activity. This typically involves a malicious document exploiting MSBuild to execute arbitrary code. Such attacks are concerning because they blend malicious actions with legitimate system tools, making detection challenging. This activity has been observed since at least early 2020 and continues to evolve. Defenders should prioritize monitoring process relationships and command-line arguments involving MSBuild.exe.

## Attack Chain

1. A user receives a phishing email containing a malicious Microsoft Office document (e.g., Word, Excel).
2. The user opens the document, potentially after being socially engineered to disable security warnings.
3. The document contains an embedded OLE object or macro that, when executed, initiates a process.
4. The Office application (e.g., winword.exe, excel.exe) spawns the `MSBuild.exe` process.
5. MSBuild.exe executes a project file (e.g., `.csproj`, `.xml`) containing malicious code or commands.
6. This code downloads and executes a payload from a remote server.
7. The payload establishes persistence through registry modifications or scheduled tasks.
8. The attacker achieves their objective, such as data exfiltration, lateral movement, or deploying ransomware.

## Impact

A successful attack can lead to a full system compromise, enabling attackers to steal sensitive data, install malware, or disrupt business operations. The use of MSBuild for malicious purposes allows attackers to bypass application whitelisting and other security controls, increasing the likelihood of a successful breach. Office applications are ubiquitous, making this technique highly scalable across various sectors.

## Recommendation

*   Deploy the Sigma rule "Microsoft Build Engine Started by an Office Application" to your SIEM and tune for your environment.
*   Enable Sysmon process-creation logging to capture the parent-child relationships required by the Sigma rule.
*   Investigate any instances of `MSBuild.exe` spawned by Office applications, focusing on command-line arguments and network connections.
*   Review and strengthen your organization's email security policies to prevent phishing attacks.
