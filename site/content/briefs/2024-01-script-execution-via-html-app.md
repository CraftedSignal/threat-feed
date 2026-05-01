---
title: Script Execution via Microsoft HTML Application
slug: 2024-01-script-execution-via-html-app
description: Detects the execution of scripts via HTML applications using Windows utilities rundll32.exe or mshta.exe to bypass defenses by proxying execution of malicious content with signed binaries.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - script-execution
  - windows
vendors:
  - Microsoft
  - Citrix
  - Quokka.Works
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Windows
  - Citrix System32
  - MSACCESS.EXE
  - GTInstaller
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Microsoft Defender XDR
  - Crowdstrike FDR
  - Elastic Endgame
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_script_via_html_app.toml
rules:
  - title: Script Execution via Microsoft HTML Application
    description: Detects the execution of scripts via HTML applications using Windows utilities rundll32.exe or mshta.exe with suspicious command line arguments.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSHTA Execution without HTA/HTM File
    description: Detects mshta.exe execution without .hta or .htm file arguments, and with a high number of arguments.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: MSHTA Execution from Archive or Temp Directory
    description: Detects mshta.exe execution from common archive extraction or temporary directories.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection identifies the execution of scripts via HTML applications, leveraging Windows utilities like `rundll32.exe` or `mshta.exe`. Attackers often use this method to bypass process and signature-based defenses by proxying the execution of malicious content through legitimate, signed binaries. The detection focuses on specific command-line arguments and patterns associated with this technique, while also excluding known legitimate uses by applications such as Citrix System32 (`wfshell.exe`), Microsoft Access (`MSACCESS.EXE`), and Quokka.Works (`GTInstaller.exe`). This technique is used by attackers to execute malicious scripts without directly running them, thus evading traditional security measures. The detection rule analyzes process names, command-line arguments, parent processes, and file paths to identify potentially malicious activity indicative of defense evasion.

## Attack Chain

1. An attacker gains initial access through various means (e.g., phishing, drive-by download).
2. The attacker leverages a malicious HTML application (HTA) file or a scriptlet (SCT) file.
3. The attacker uses `mshta.exe` or `rundll32.exe` to execute the malicious HTA or SCT file. The command line includes obfuscated or encoded script content.
4. `mshta.exe` or `rundll32.exe` process spawns a child process, such as `cmd.exe` or `powershell.exe`, to execute further commands.
5. The spawned process executes malicious code, such as downloading and executing a payload.
6. The attacker achieves persistence by modifying registry keys or creating scheduled tasks.
7. The attacker performs lateral movement by exploiting vulnerabilities or using stolen credentials.
8. The final objective is achieved, such as data exfiltration, ransomware deployment, or system compromise.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to compromise the system, steal sensitive data, deploy ransomware, or establish a persistent foothold. Due to the nature of the technique, it can bypass many traditional security measures. The wide adoption of Windows and the inherent trust placed in signed binaries makes this a potent evasion technique. Failure to detect and prevent this attack can lead to significant financial and reputational damage for the targeted organization.

## Recommendation

*   Deploy the Sigma rule "Script Execution via Microsoft HTML Application" to your SIEM to detect suspicious `mshta.exe` and `rundll32.exe` executions. Tune the rule by adding exceptions for known legitimate uses in your environment.
*   Enable Sysmon process creation logging (Event ID 1) to ensure the visibility required for the Sigma rules to function correctly.
*   Monitor process command lines for suspicious arguments like "script:eval", "WScript.Shell", and "mshta http" which are indicative of this technique.
*   Implement application control policies to restrict the execution of `mshta.exe` and `rundll32.exe` where they are not required for legitimate business purposes.
*   Investigate and block any identified malicious HTA files or scriptlet URLs found in the command lines of detected processes.
