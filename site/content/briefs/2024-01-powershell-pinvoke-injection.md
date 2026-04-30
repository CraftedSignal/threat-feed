---
title: PowerShell P/Invoke API Chain for Process Injection
slug: 2024-01-powershell-pinvoke-injection
description: This brief details detection of PowerShell scripts leveraging P/Invoke API calls to perform process injection, covering techniques like self-injection, remote thread injection, APC injection, thread-context hijacking, process hollowing, section-map injection, reflective DLL loading, and DLL injection.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - process-injection
  - powershell
  - pinvoke
vendors:
  - Microsoft
products:
  - PowerShell
affected_os:
  - Windows
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
  - title: PowerShell Add-Type DllImport Definition
    description: Detects PowerShell scripts that use Add-Type to define .NET classes with DllImport attributes, indicating potential P/Invoke usage for process injection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1059.001
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: PowerShell PInvoke API Call Sequence
    description: Detects PowerShell scripts that invoke a sequence of API calls commonly used for process injection, such as VirtualAlloc, WriteProcessMemory, and CreateRemoteThread.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1059.001
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Static Method Invocation with IntPtr Zero
    description: Detects PowerShell scripts utilizing static method invocation patterns with IntPtr::Zero, often associated with P/Invoke and process injection techniques.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This brief focuses on the detection of PowerShell scripts utilizing Platform Invoke (P/Invoke) to perform process injection. P/Invoke allows managed code (PowerShell) to call native, unmanaged code (Windows API functions). Adversaries leverage this capability to inject malicious code into other processes, bypassing traditional defenses. This activity is identified through PowerShell script block logging (Event ID 4104). The detection strategy covers both the compile phase (detecting inline .NET class definitions with DllImport declarations) and the execution phase (detecting static method invocation patterns using ::MethodName syntax with execution context indicators). This ensures broad coverage, even when pre-compiled assemblies are loaded. The techniques detected cover a wide range of process injection methods, increasing the likelihood of detection against various attack vectors.

## Attack Chain

1.  The attacker executes a PowerShell script containing malicious code designed for process injection.
2.  The script uses `Add-Type -TypeDefinition` to define a .NET class inline, embedding C# source code that includes `[DllImport]` declarations for Windows API functions.
3.  The `DllImport` attribute specifies the native DLL (e.g., kernel32.dll, ntdll.dll) and the function name to import.
4.  The script declares external functions like `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateSection`, and `NtMapViewOfSection` using `extern <ReturnType> <FunctionName>`.
5.  The script uses static method invocation (e.g., `[IntPtr]::Zero`, `[Marshal]::Copy`) to call the declared functions.
6.  The script allocates memory in the target process using `VirtualAllocEx` or `NtAllocateVirtualMemory`.
7.  The malicious code (shellcode or DLL) is written to the allocated memory using `WriteProcessMemory`.
8.  A new thread is created in the target process to execute the injected code using `CreateRemoteThread` or `RtlCreateUserThread`. Alternatively, APC injection uses `QueueUserAPC` to queue an Asynchronous Procedure Call in the target process.

## Impact

Successful process injection allows attackers to execute arbitrary code within the context of a legitimate process. This can lead to privilege escalation, credential theft, and persistence. Process injection can also be used to bypass security software and gain unauthorized access to sensitive data. This technique has been observed in malware campaigns associated with VIP Keylogger and similar threats, leading to data exfiltration and system compromise.

## Recommendation

*   Enable PowerShell script block logging (Event ID 4104) to capture the necessary data for detection.
*   Deploy the provided Sigma rules to your SIEM to detect malicious PowerShell scripts using P/Invoke for process injection.
*   Investigate any alerts generated by the Sigma rules, focusing on processes that exhibit suspicious API call patterns.
*   Review and tune the Sigma rules based on your environment to minimize false positives and ensure accurate detection.
