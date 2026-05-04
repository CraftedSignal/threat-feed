---
title: PowerShell P/Invoke Process Injection API Chain Detection
slug: 2024-01-powershell-pinvoke-process-injection
description: This analytic detects PowerShell code that uses P/Invoke to call Windows API functions associated with process injection, such as VirtualAlloc, WriteProcessMemory, and CreateRemoteThread, indicating potential malicious activity.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - process-injection
  - powershell
  - pinvoke
  - defense-evasion
vendors:
  - Microsoft
  - Splunk
products:
  - PowerShell
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1620
    technique_name: Reflective Code Loading
references:
  - https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute
  - https://www.ired.team/offensive-security/code-injection-process-injection
  - https://www.broadcom.com/support/security-center/protection-bulletin/vip-keylogger-spreads-via-multi-org-impersonation-campaign
  - https://attack.mitre.org/techniques/T1055/
  - https://attack.mitre.org/techniques/T1620/
rules:
  - title: PowerShell PInvoke Process Injection
    description: Detects PowerShell scripts using P/Invoke to call Windows API functions indicative of process injection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1055.001
      - T1547.001
    data_sources:
      - powershell
      - windows
  - title: PowerShell CreateProcess SetThreadContext ResumeThread Injection
    description: Detects PowerShell scripts using CreateProcess, VirtualAlloc, WriteProcessMemory, SetThreadContext and ResumeThread indicative of process injection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1055.001
      - T1547.001
    data_sources:
      - powershell
      - windows
rules_count: 2
---

This detection identifies PowerShell scripts leveraging the P/Invoke (Platform Invoke) technology to perform process injection. P/Invoke allows managed code (like PowerShell) to call unmanaged functions exported from DLLs, including critical Windows API functions. Attackers use this to inject malicious code into legitimate processes for evasion and persistence. The detection focuses on identifying specific API chains commonly used in process injection techniques, such as allocating memory in a target process (VirtualAlloc), writing malicious code into the allocated memory (WriteProcessMemory), and executing the injected code (CreateRemoteThread). This activity is often associated with malware deployment, privilege escalation, and defense evasion. The detection logic is designed to identify these API chains either at the compile phase using Add-Type or during the execution phase, alerting on suspicious PowerShell behavior.

## Attack Chain

1.  Attacker gains initial access to the system, potentially through phishing or exploiting a vulnerability.
2.  PowerShell is invoked to execute a malicious script.
3.  The PowerShell script uses Add-Type and DllImport to declare external functions from Windows DLLs, including kernel32.dll and ntdll.dll.
4.  The script uses functions such as OpenProcess to gain a handle to a target process.
5.  VirtualAllocEx is called to allocate memory within the target process.
6.  WriteProcessMemory is used to write malicious code into the allocated memory region of the target process.
7.  CreateRemoteThread is called to create a new thread within the target process, pointing to the injected code.
8.  The injected code executes within the context of the target process, achieving code execution and potential privilege escalation.

## Impact

Successful process injection allows attackers to execute arbitrary code within the context of a trusted process, bypassing security controls and potentially gaining elevated privileges. This can lead to data theft, system compromise, or further propagation within the network. The use of PowerShell and P/Invoke makes detection more challenging, as the activity can blend in with legitimate system administration tasks. A successful attack could lead to the deployment of a VIP Keylogger or other malware, as noted in the provided references.

## Recommendation

*   Enable PowerShell Script Block Logging (Event ID 4104) to provide the necessary data for detection (data_source).
*   Deploy the Sigma rule `PowerShell PInvoke Process Injection` to your SIEM and tune the rule to your environment (rules).
*   Investigate any alerts generated by the Sigma rule, focusing on the specific API chains identified in the `detection` section of the rule.
*   Review PowerShell execution policies and restrict the execution of unsigned scripts to reduce the attack surface.
