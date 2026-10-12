---
title: Abuse of MSIExec DLLRegisterServer for Proxy Execution
slug: 2026-10-msiexec-dllregisterserver
description: Adversaries abuse the msiexec.exe /y command-line switch to trigger the DLLRegisterServer function, facilitating malicious DLL loading for defense evasion and persistence.
date: "2026-10-12T18:15:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - living-off-the-land
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The following analytic detects the execution of msiexec.exe with the /y switch parameter, which enables the loading of DLLRegisterServer.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This activity is significant because it can indicate an attempt to register malicious DLLs, potentially leading to code execution or persistence on the system.
    confidence_band: high
rules:
  - title: Detect Suspicious MSIExec DLLRegisterServer Execution
    description: Detects the execution of msiexec.exe with the /y or -y parameter, which triggers DLLRegisterServer and is a common technique for proxy execution of malicious DLLs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to SIEM to detect msiexec.exe /y usage.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides analytic logic for msiexec.exe /y.
  hunt_leads:
    - lead: Search for instances of msiexec.exe where the command line contains '/y' or '-y'.
      technique_id: T1218.007
      data_needed:
        - Command-line arguments from process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source highlights this specific flag as the indicator.
---

The Windows Installer utility, msiexec.exe, is a legitimate system binary that can be abused for proxy execution. By invoking msiexec.exe with the /y or -y command-line switch, an attacker triggers the DLLRegisterServer function. This behavior allows the execution of code within the context of the installer process, often used to load arbitrary, malicious DLLs. This technique is frequently observed in post-exploitation scenarios, including those linked to the 'Water Gamayun' activity group, as a means to achieve code execution, escalate privileges, or maintain persistence on a target system. Because msiexec.exe is a trusted, signed binary, its use to execute malicious code serves as a effective defense evasion strategy. Defenders should monitor process command-line arguments and parent-child process relationships to identify unauthorized usage of these specific flags.

## Attack Chain

1. Attacker gains initial access to a Windows endpoint.
2. Attacker writes a malicious DLL file to a directory on the local file system.
3. Attacker identifies a parent process from which to spawn the malicious installer command.
4. Attacker executes msiexec.exe with the /y or -y flag, providing the path to the malicious DLL.
5. The DLLRegisterServer function is invoked by msiexec.exe, executing the entry point of the malicious DLL.
6. Malicious code executes within the context of the trusted system binary.
7. Attacker achieves persistence or further system access through the loaded malicious code.

## Impact

Successful exploitation of this technique allows adversaries to execute arbitrary code with the privileges of the msiexec.exe process. This can lead to full system compromise, the installation of persistent backdoors, and facilitates further lateral movement within the target environment.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious process execution patterns involving msiexec.exe and the /y flag.
* Implement Sysmon Event ID 1 or Windows Security Event ID 4688 to capture full command-line arguments for all process creation events.
* Tune internal allowlists for legitimate MSI software installation processes to minimize false positives from administrative activity.
