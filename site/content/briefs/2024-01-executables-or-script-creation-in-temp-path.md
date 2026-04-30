---
title: Executable or Script Creation in Temporary Paths
slug: 2024-01-executables-or-script-creation-in-temp-path
description: Adversaries may create executables or scripts in temporary directories to evade detection, maintain persistence, and execute unauthorized code on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - persistence
  - privilege-escalation
  - execution
  - temp-directory
  - file-creation
vendors:
  - Microsoft
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/executables_or_script_creation_in_temp_path.yml
  - https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - https://twitter.com/pr0xylife/status/1590394227758104576
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
rules:
  - title: Executable or Script Creation in Temp Path
    description: Detects the creation of executable or script files in common temporary directories.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1036
    data_sources:
      - file_event
      - windows
  - title: Process Spawning from Temporary Directory
    description: Detects processes being executed from a temporary directory, which is often indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the creation of executable files or scripts within temporary directories on Windows systems, a common tactic used by adversaries to bypass security controls and establish persistence. This behavior is often indicative of malicious activity, such as malware installation, privilege escalation, or unauthorized code execution. The observed activity involves writing files with extensions like `.exe`, `.dll`, `.ps1`, and `.bat` into common temporary locations like `\Windows\Temp\` or `\AppData\Local\Temp\`. This technique allows attackers to hide malicious files among legitimate temporary files, making detection more challenging. References to campaigns like Volt Typhoon, and ransomware families like LockBit highlight the importance of detecting this behavior.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker drops a malicious executable or script onto the compromised system.
3.  To evade detection, the malicious file is created in a temporary directory such as `C:\Windows\Temp\` or `C:\Users\<username>\AppData\Local\Temp\`.
4.  The attacker uses a dropper or installer to write the malicious file (e.g., using `cmd.exe`, `powershell.exe`).
5.  The attacker may rename the file to further disguise its purpose.
6.  The attacker executes the malicious file, potentially leading to code execution, privilege escalation, or persistence.
7.  The executed malware performs malicious actions, such as lateral movement, data exfiltration, or ransomware deployment.
8.  The attacker maintains persistence on the system, ensuring continued access and control.

## Impact

Successful exploitation can lead to unauthorized code execution, privilege escalation, and persistent access within the targeted environment. This can result in data theft, system compromise, or ransomware deployment. The references to campaigns like Volt Typhoon and ransomware families like LockBit highlight the potential for significant disruption and financial loss. Multiple analytic stories, such as AsyncRAT, DarkGate Malware, and Qakbot, highlight the prevalence of this technique across various threat actors.

## Recommendation

*   Enable Sysmon EventID 11 (FileCreate) logging to monitor file creation events on endpoints.
*   Deploy the Sigma rule "Executable or Script Creation in Temp Path" to your SIEM and tune for your environment.
*   Investigate any file creation events in temporary directories involving executable or script file types (.exe, .dll, .ps1, .bat, etc.).
*   Review and filter events based on your organization's normal activity to reduce false positives, as mentioned in the "known_false_positives" section of the source.
*   Monitor for processes spawned from temporary directories, using a process creation monitoring tool and correlate with other suspicious activities.
