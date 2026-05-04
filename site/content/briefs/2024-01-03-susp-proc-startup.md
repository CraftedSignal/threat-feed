---
title: Execution of Persistent Suspicious Programs via Run Keys
slug: 2024-01-03-susp-proc-startup
description: This analytic identifies suspicious programs such as script interpreters, rundll32, or MSBuild being executed shortly after user logon, indicating potential persistence mechanisms abusing the registry run keys.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - threat-detection
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_runtime_run_key_startup_susp_procs.toml
rules:
  - title: Persistent Suspicious Program Execution
    description: Detects suspicious processes (script interpreters, rundll32, etc.) being executed shortly after user logon, indicating potential persistence mechanisms abusing the registry run keys.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSBuild Execution in Startup
    description: Detects MSBuild.exe being executed from suspicious locations shortly after user logon, indicative of potential persistence abuse or defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1127.001
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule detects a common persistence technique where attackers configure malicious scripts or programs to run automatically after a user logs on to a Windows system. The technique abuses the Registry Run keys and Startup folders to achieve persistence. The rule specifically identifies processes launched shortly after the userinit.exe and explorer.exe processes start, focusing on processes known to be used for malicious purposes, such as cscript.exe, wscript.exe, PowerShell.exe, MSHTA.exe, RUNDLL32.exe, REGSVR32.exe, RegAsm.exe, MSBuild.exe, and InstallUtil.exe. Additionally, it checks if these processes are launched from or access suspicious paths like C:\Users*, C:\ProgramData*, and C:\Windows\Temp*. This detection is crucial because it helps identify potentially malicious activities that bypass standard security measures by leveraging legitimate system tools.

## Attack Chain

1.  The attacker gains initial access to the system, typically through phishing, exploiting vulnerabilities, or using stolen credentials (not covered in the source).
2.  The attacker modifies the Windows Registry Run keys (HKCU\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\Software\Microsoft\Windows\CurrentVersion\Run) to execute a malicious program or script.
3.  The system starts, and the winlogon.exe process initiates userinit.exe.
4.  userinit.exe starts explorer.exe, loading the user's profile and desktop environment.
5.  The Registry Run keys are processed, and the malicious program or script is executed as a child process of explorer.exe. This often involves suspicious processes like `cscript.exe`, `powershell.exe`, or `rundll32.exe`.
6.  The malicious process executes from a suspicious location, such as `C:\\Users\\*`, `C:\\ProgramData\\*`, or `C:\\Windows\\Temp\\*`.
7.  The malicious process performs its intended actions, such as downloading additional malware, establishing command and control, or exfiltrating data.
8.  The system remains infected, with the malicious process running every time the user logs on, ensuring persistence.

## Impact

A successful attack can lead to persistent malware infections, data theft, and complete system compromise. Attackers can maintain long-term access to the compromised system, potentially leading to further lateral movement within the network. This can result in significant financial losses, reputational damage, and operational disruptions.

## Recommendation

*   Deploy the Sigma rule "Persistent Suspicious Program Execution" to detect suspicious processes executed shortly after user logon (rule).
*   Enable process creation logging via Sysmon or Elastic Defend to provide the data required for the Sigma rule to function effectively.
*   Investigate any alerts generated by the Sigma rule by examining the process lineage and command-line arguments of the suspicious processes.
*   Implement strict access controls and regularly audit user accounts to prevent unauthorized modifications to the Registry Run keys.
*   Block execution of the listed suspicious processes (`cscript.exe`, `wscript.exe`, `PowerShell.EXE`, `MSHTA.EXE`, `RUNDLL32.EXE`, `REGSVR32.EXE`, `RegAsm.exe`, `MSBuild.exe`, `InstallUtil.exe`) from suspicious paths (`C:\\Users\\*`, `C:\\ProgramData\\*`, `C:\\Windows\\Temp\\*`) via application control policies (overview).
