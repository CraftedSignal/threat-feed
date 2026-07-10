---
title: Suspicious Managed Code Hosting Process
slug: 2024-01-suspicious-managed-code-hosting
description: The rule identifies suspicious managed code hosting processes (wscript.exe, cscript.exe, mshta.exe, wmic.exe, svchost.exe, dllhost.exe, cmstp.exe, regsvr32.exe), which could indicate code injection or other forms of suspicious code execution on Windows systems, often used for defense evasion.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
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
    technique_id: T1620
    technique_name: Reflective Code Loading
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://attack.mitre.org/techniques/T1055/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/003/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1218/010/
  - https://attack.mitre.org/techniques/T1620/
  - https://attack.mitre.org/techniques/T1047/
  - http://web.archive.org/web/20230329154538/https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html
rules:
  - title: Suspicious Managed Code Hosting Process File Creation
    description: Detects the creation of log files by suspicious managed code hosting processes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - file_event
      - windows
  - title: Suspicious CMSTP Execution
    description: Detects the execution of cmstp.exe with suspicious parameters.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule detects the execution of potentially malicious managed code hosting processes on Windows systems. Adversaries frequently abuse legitimate Windows utilities such as `wscript.exe`, `cscript.exe`, `mshta.exe`, `wmic.exe`, `svchost.exe`, `dllhost.exe`, `cmstp.exe`, and `regsvr32.exe` to bypass security controls, execute arbitrary code, and evade detection. These processes can be used for various malicious activities, including executing scripts, injecting code into other processes, and downloading/executing payloads from the internet. The rule monitors file creation events associated with these processes to identify suspicious activity. The detection logic is based on data from Elastic Defend, Sysmon, Microsoft Defender XDR, SentinelOne, Elastic Endgame, and Crowdstrike.

## Attack Chain

1.  Adversary gains initial access to the system (e.g., via phishing or exploiting a vulnerability).
2.  The adversary uses a system binary proxy execution technique, such as `mshta.exe`, to execute malicious code.
3.  `Mshta.exe` executes an HTML Application (.hta) file, which contains embedded VBScript or JavaScript code.
4.  The script downloads and executes a malicious payload from a remote server.
5.  Alternatively, the adversary uses `regsvr32.exe` to proxy execution of a malicious DLL.
6.  `Regsvr32.exe` executes the DLL, which performs malicious actions, such as injecting code into other processes or establishing persistence.
7.  The injected code allows the adversary to perform further actions on the system, such as data exfiltration or lateral movement.
8.  The adversary achieves their final objective, such as data theft, system compromise, or ransomware deployment.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to gain control of the compromised system, steal sensitive data, or deploy malware. Widespread use of these techniques can compromise entire networks, leading to significant financial losses and reputational damage. The use of LOLBins makes attribution difficult, as these are signed Microsoft binaries and may be whitelisted in some environments.

## Recommendation

*   Deploy the Sigma rule `Suspicious Managed Code Hosting Process File Creation` to your SIEM to detect the creation of log files by managed code hosting processes.
*   Enable Sysmon file creation logging to provide the necessary data for the Sigma rules to function correctly.
*   Monitor process execution events for the managed code hosting processes listed in the overview (`wscript.exe`, `cscript.exe`, `mshta.exe`, `wmic.exe`, `svchost.exe`, `dllhost.exe`, `cmstp.exe`, `regsvr32.exe`).
*   Investigate any alerts generated by the Sigma rule, focusing on identifying the parent process and any network connections made by the managed code hosting process.
*   Implement application control policies to restrict the execution of scripts and executables in untrusted locations.
