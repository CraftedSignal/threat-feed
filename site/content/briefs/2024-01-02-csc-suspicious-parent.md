---
title: Suspicious CSC.exe Parent Process
slug: 2024-01-02-csc-suspicious-parent
description: The Csc.exe (C# compiler) process is being launched by unusual parent processes or from suspicious locations, indicating potential malware execution or defense evasion.
date: "2024-01-02T15:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - attack.execution
  - attack.defense-evasion
  - csc.exe
  - payload-delivery
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.uptycs.com/blog/warzonerat-can-now-evade-with-process-hollowing
  - https://reaqta.com/2017/11/short-journey-darkvnc/
  - https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_csc_susp_parent.yml
rules:
  - title: Csc.exe Executed by Scripting Host
    description: Detects Csc.exe being executed by scripting hosts (cscript, wscript) which is often indicative of malicious script execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: Csc.exe Executed by Office Application
    description: Detects Csc.exe being executed by Microsoft Office applications (Excel, Word, PowerPoint), which could indicate exploitation of macros.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: Csc.exe Executed from Suspicious Location
    description: Detects Csc.exe being executed with a parent process command line referencing suspicious file locations, such as temp directories.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers are leveraging the legitimate Csc.exe (C# compiler) to execute malicious code, often as a part of defense evasion or payload delivery. This is achieved by spawning Csc.exe from unusual parent processes such as scripting hosts (cscript.exe, wscript.exe), Office applications (excel.exe, winword.exe), or PowerShell, especially when combined with encoded commands. Observed techniques also include launching Csc.exe from temporary or unusual directories. This activity bypasses traditional application whitelisting and can lead to the execution of arbitrary code. This activity has been associated with WarzoneRAT, DarkVNC, and the delivery of IMAPLoader malware.

## Attack Chain

1. An attacker gains initial access, potentially through phishing or exploiting a vulnerability.
2. A script or Office macro executes, initiating a command-line process.
3. This process then invokes a scripting host (e.g., cscript.exe) or PowerShell.
4. The scripting host or PowerShell executes a command that downloads or creates a C# source code file.
5. Csc.exe is then invoked, often from a temporary directory, to compile the downloaded/created C# code.
6. The compiled C# code executes, performing malicious actions.
7. The malicious code may establish persistence, communicate with a C2 server, or perform data exfiltration.
8. The final objective might be to deploy ransomware, steal sensitive data, or establish a persistent backdoor.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to compromise systems, steal data, or deploy malware. Depending on the user's permissions, the attacker could gain elevated privileges. The observed techniques have been associated with ransomware deployment, data theft, and remote access trojans (RATs).

## Recommendation

*   Deploy the Sigma rule "Csc.EXE Execution Form Potentially Suspicious Parent" to detect suspicious parent processes of csc.exe.
*   Monitor process creation events for csc.exe with parent processes like scripting hosts or Office applications.
*   Investigate any instances of csc.exe being executed from temporary directories or user profile locations by reviewing process_creation logs.
*   Enable Sysmon process creation logging to capture detailed process information, including parent-child relationships, for effective detection.
