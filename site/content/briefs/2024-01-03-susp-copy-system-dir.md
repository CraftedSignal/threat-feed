---
title: Suspicious Copy from or to System Directory
slug: 2024-01-03-susp-copy-system-dir
description: This threat involves the suspicious copying of files from or to Windows system directories (System32, SysWOW64, WinSxS) using command-line tools, often employed by attackers to relocate LOLBINs for defense evasion.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - defense-evasion
  - lolbin
  - windows
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120
  - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
  - https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/
rules:
  - title: Suspicious Copy From System Directory with CMD
    description: Detects a suspicious copy operation from a system directory using cmd.exe
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1036.003
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Copy From System Directory with PowerShell
    description: Detects a suspicious copy operation from a system directory using PowerShell
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1036.003
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Copy From System Directory with Robocopy/Xcopy
    description: Detects a suspicious copy operation from a system directory using robocopy.exe or xcopy.exe
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1036.003
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers often copy legitimate operating system binaries (LOLBINs) from standard system directories to evade detection. This technique involves using command-line tools like `cmd.exe`, `powershell.exe`, `robocopy.exe`, or `xcopy.exe` to move these binaries to different locations on the disk, frequently with modified names. By relocating and renaming LOLBINs, threat actors attempt to bypass security measures that rely on file path or filename-based detection. This technique has been observed in various attack campaigns, including those involving malware delivery and ransomware deployment. This behavior aims to execute malicious operations under the guise of legitimate system processes, complicating forensic analysis and incident response efforts.

## Attack Chain

1.  Initial access is achieved through an undisclosed method (e.g., exploitation, phishing).
2.  The attacker gains command execution on the target system.
3.  The attacker uses `cmd.exe` or `powershell.exe` to initiate a copy operation.
4.  The command line includes the `copy` command, `copy-item`, `cp`, or `cpi` to copy a file.
5.  The source file is located within a Windows system directory such as `C:\\Windows\\System32`, `C:\\Windows\\SysWOW64`, or `C:\\Windows\\WinSxS`.
6.  The destination directory is outside the standard system directories.
7.  The copied binary is then executed from the new location.
8.  The attacker uses the LOLBIN to perform further malicious actions, such as downloading payloads or executing arbitrary code.

## Impact

Successful execution of this attack allows threat actors to evade traditional security detections by using renamed and relocated LOLBINs. This can lead to the successful execution of malicious payloads, potentially resulting in data theft, system compromise, or ransomware deployment. The impact can range from localized infections to domain-wide ransomware attacks, depending on the attacker's objectives and the scope of the compromise.

## Recommendation

*   Deploy the Sigma rule "Suspicious Copy From or To System Directory" to your SIEM to detect this behavior and tune for your environment.
*   Investigate any `process_creation` events where `cmd.exe` or `powershell.exe` is used to copy files from system directories as indicated by the rule and the details in the Attack Chain section.
*   Monitor for the execution of LOLBINs such as `certutil.exe`, `robocopy.exe`, and `xcopy.exe` from non-standard locations.
*   Implement application control policies to restrict the execution of unauthorized or relocated binaries.
