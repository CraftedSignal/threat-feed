---
title: HTML Help Executable Spawning Child Processes
slug: 2024-01-html-help-spawn
description: The execution of hh.exe (HTML Help) spawning a child process indicates the use of a Compiled HTML Help (CHM) file to execute potentially malicious Windows script code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - html-help
  - chm
  - lolbas
  - process-creation
vendors:
  - Microsoft
products:
  - Microsoft Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1218/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md
  - https://lolbas-project.github.io/lolbas/Binaries/Hh/
  - https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7
  - https://web.archive.org/web/20220119133748/https://cyberforensicator.com/2019/01/20/silence-dissecting-malicious-chm-files-and-performing-forensic-analysis/
rules:
  - title: Detect HTML Help Spawning CMD
    description: Detects hh.exe (HTML Help) spawning cmd.exe as a child process.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
  - title: Detect HTML Help Spawning PowerShell
    description: Detects hh.exe (HTML Help) spawning powershell.exe as a child process.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse the HTML Help executable (hh.exe) to execute malicious code on a target system. Compiled HTML Help (CHM) files can contain embedded scripts or links to external resources. When a CHM file is opened, hh.exe renders the content, potentially triggering the execution of malicious scripts. This technique is often used to bypass security controls and deliver malware. This behavior is significant as it may indicate an attempt to execute malicious scripts via CHM files, a known technique for bypassing security controls. If confirmed malicious, this could lead to unauthorized code execution, potentially compromising the system. The LOLBAS project documents this use of hh.exe, and it has been observed in use by various threat actors.

## Attack Chain

1. An attacker crafts a malicious CHM file containing embedded scripts or links.
2. The CHM file is delivered to the victim via email or other means.
3. The victim opens the CHM file, which is processed by hh.exe.
4. Hh.exe renders the HTML content within the CHM file.
5. The embedded script (e.g., JavaScript, VBScript) or link is executed.
6. The script spawns a child process (e.g., cmd.exe, powershell.exe) using ShellExecute or similar methods.
7. The child process executes arbitrary commands, downloads malware, or performs other malicious actions.
8. The attacker gains control of the system or exfiltrates data.

## Impact

Successful exploitation of this technique can lead to arbitrary code execution, allowing the attacker to compromise the system. This can result in data theft, installation of malware, or further propagation within the network. The number of potential victims is broad, as CHM files can be distributed through various channels. The impact ranges from individual workstation compromise to widespread organizational breaches.

## Recommendation

*   Monitor process creation events for hh.exe spawning child processes to detect potential malicious activity, as described in the overview.
*   Implement the Sigma rule `Detect HTML Help Spawning CMD` to identify instances of hh.exe spawning command interpreters.
*   Deploy the Sigma rule `Detect HTML Help Spawning PowerShell` to detect instances of hh.exe spawning PowerShell processes.
*   Enable Sysmon process creation logging to capture the necessary process execution data.
*   Block known malicious CHM files based on file hash (if available from threat intelligence feeds, although none are included here).
