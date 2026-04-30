---
title: Suspicious Script Interpreter Execution from Environment Variable Folders
slug: 2024-01-susp-script-exec
description: Adversaries may execute script interpreters such as cscript, wscript, mshta, or powershell from suspicious directories accessible via environment variables to evade detection and execute malicious scripts.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - attack.execution
  - attack.t1059
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.virustotal.com/gui/file/91ba814a86ddedc7a9d546e26f912c541205b47a853d227756ab1334ade92c3f
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-russia-ukraine-military
  - https://learn.microsoft.com/en-us/windows/win32/shell/csidl
rules:
  - title: Suspicious PowerShell Execution from Temp Folders
    description: Detects PowerShell execution from common temp folders with bypass flags.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Script Interpreter from User Profile Folders
    description: Detects cscript, wscript, or mshta executing from user profile directories like Favorites or Contacts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often leverage script interpreters like cscript.exe, wscript.exe, mshta.exe, and powershell.exe to execute malicious code. This activity becomes more suspicious when these interpreters are launched from directories referenced by environment variables commonly associated with temporary storage, such as %TEMP%, %PUBLIC%, or within user profile directories like Favorites or Contacts. This behavior is often indicative of malware attempting to evade detection by residing in locations less scrutinized by security tools. Such techniques are employed to execute malicious scripts downloaded from the internet or dropped by other malware components. This behavior has been linked to threat actors such as Shuckworm, known for targeting Ukraine with military-themed lures.

## Attack Chain

1. A user downloads a malicious file (e.g., a document or executable) from the internet or receives it via email.
2. The malicious file, upon execution, drops a script file (e.g., VBScript, JavaScript, PowerShell script) into a temporary directory like C:\Users\Public\ or C:\Users\<username>\AppData\Local\Temp\.
3. The dropped script uses obfuscation and/or encoding techniques to avoid static analysis.
4. The attacker executes a script interpreter (cscript.exe, wscript.exe, mshta.exe, powershell.exe) to run the malicious script from the temporary directory. The command line often includes bypass flags such as `-ExecutionPolicy Bypass` or `-w hidden` to evade security controls.
5. The script interpreter executes the malicious code, which may involve downloading additional payloads, establishing persistence, or performing lateral movement.
6. The malicious script may modify registry keys to establish persistence by adding a run key or scheduled task.
7. The script may attempt to connect to command-and-control (C2) servers to receive further instructions and exfiltrate sensitive data.
8. The final objective may include data theft, system compromise, or deployment of ransomware.

## Impact

Successful exploitation can lead to the execution of arbitrary code, system compromise, and data exfiltration. Depending on the attacker's objectives, the impact can range from data theft to full system control and ransomware deployment. The exploitation of scripting engines can bypass application control policies and other security measures, leading to widespread infection and significant disruption of business operations.

## Recommendation

*   Deploy the Sigma rule "Script Interpreter Execution From Suspicious Folder" to your SIEM to detect suspicious script execution from temporary directories.
*   Review and tune the filters in the Sigma rule for your environment to reduce false positives, especially related to software installation processes.
*   Enable process creation logging with command-line arguments to provide the necessary data for the Sigma rule to function effectively.
*   Monitor PowerShell execution policies and restrict script execution to signed scripts only to prevent the execution of unsigned malicious scripts.
*   Implement application control policies to restrict the execution of script interpreters from untrusted locations.
