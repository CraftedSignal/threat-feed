---
title: MSBuild Process Injection Detection
slug: 2024-01-msbuild-process-injection
description: The Microsoft Build Engine (MSBuild) is being abused to perform process injection by creating threads in other processes, a technique used to evade detection and potentially escalate privileges.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - privilege-escalation
  - process-injection
vendors:
  - Microsoft
products:
  - MSBuild
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://attack.mitre.org/techniques/T1055/
  - https://attack.mitre.org/techniques/T1127/
  - https://attack.mitre.org/techniques/T1127/001/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_injection_msbuild.toml
rules:
  - title: MSBuild CreateRemoteThread Detection
    description: Detects MSBuild creating a thread in another process, indicative of process injection.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1055
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSBuild Call Trace
    description: Detects suspicious API calls within MSBuild process executions that might indicate process injection or other malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1055
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft Build Engine (MSBuild) is a platform for building applications, commonly used in software development environments. Adversaries are exploiting MSBuild to perform process injection, a technique to execute malicious code within the address space of another process. This allows attackers to evade detection and potentially escalate privileges. The detection focuses on monitoring for thread creation in other processes by instances of MSBuild.exe. This activity is considered unusual outside of legitimate software development or build environments. The exploitation of MSBuild for process injection is a known technique (T1127.001) to proxy execution through trusted developer utilities.

## Attack Chain

1. An attacker gains initial access to the system through various means (e.g., compromised credentials, software vulnerability).
2. The attacker executes MSBuild.exe, either directly or through another process.
3. MSBuild.exe is used to load and execute a malicious project file or inline code.
4. The malicious code within the MSBuild project file leverages Windows API calls to create a thread in a target process.
5. The created thread injects malicious code or a payload into the target process's memory space.
6. The injected code executes within the context of the target process, potentially performing malicious activities.
7. These activities could include lateral movement, data exfiltration, or establishing persistence.

## Impact

Successful process injection can lead to a variety of malicious outcomes, including privilege escalation, data theft, and system compromise. While the specific number of victims is not available, any Windows system running MSBuild is potentially vulnerable. The use of a trusted Microsoft utility like MSBuild makes detection more difficult, as it can blend in with legitimate developer activity. This can lead to prolonged compromise and significant damage before the malicious activity is detected.

## Recommendation

*   Enable Sysmon process creation and CreateRemoteThread logging (event IDs 1 and 8) to detect the malicious activity described in the attack chain.
*   Deploy the Sigma rule "Process Injection by the Microsoft Build Engine" to your SIEM and tune for your environment to reduce false positives.
*   Implement application whitelisting to prevent unauthorized execution of MSBuild.exe in non-development environments.
*   Monitor the parent processes of MSBuild.exe for unusual or suspicious activity.
