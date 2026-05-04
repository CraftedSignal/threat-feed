---
title: Process Activity via Compiled HTML File Execution
slug: 2024-01-compiled-html-execution
description: Adversaries may conceal malicious code in compiled HTML files (.chm) and deliver them to a victim for execution, using the HTML Help executable (hh.exe) to proxy the execution of scripting interpreters and bypass security controls.
date: "2024-01-03T18:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - defense-evasion
  - compiled-html
  - windows
  - proxy-execution
vendors:
  - Microsoft
  - Elastic
products:
  - Microsoft HTML Help system
  - Elastic Defend
  - Microsoft Defender XDR
  - Sysmon
  - SentinelOne Cloud Funnel
  - CrowdStrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/001/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_via_compiled_html_file.toml
rules:
  - title: Compiled HTML File Spawning Suspicious Processes
    description: Detects instances where hh.exe (HTML Help executable) spawns scripting interpreters like powershell.exe, cmd.exe, or mshta.exe, which is indicative of potential malicious code execution from a compiled HTML file.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1218.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Creation Under hh.exe
    description: Detects suspicious processes being created as children of hh.exe, which can indicate exploitation of compiled HTML files.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are known to deliver malicious payloads within compiled HTML files (.chm) to bypass security measures and gain initial access to systems. This technique leverages the Microsoft HTML Help system and its associated executable, hh.exe, to proxy the execution of malicious code. Compiled HTML files can contain various types of content, including HTML documents, images, and scripting languages like VBA, JScript, Java, and ActiveX. By embedding malicious scripts or executables within a .chm file, attackers can trick users into executing them when they open the file. This is particularly effective because hh.exe is a signed binary, which may allow it to bypass certain security controls. The scope of this technique affects Windows systems where the HTML Help system is installed.

## Attack Chain

1.  The attacker crafts a malicious .chm file containing embedded malicious code, such as a PowerShell script or executable.
2.  The attacker delivers the .chm file to the victim via social engineering, such as phishing or malicious websites.
3.  The victim opens the .chm file, causing hh.exe to launch.
4.  hh.exe processes the .chm file, rendering its content, which includes the embedded malicious script or executable.
5.  The malicious code executes, often spawning a scripting interpreter like `powershell.exe` or `cmd.exe`.
6.  The scripting interpreter executes commands to download additional payloads or perform malicious actions on the system.
7.  The attacker gains initial access to the victim's system.
8.  The attacker escalates privileges and moves laterally within the network.

## Impact

Successful exploitation can lead to initial access, code execution, and potentially full system compromise. This can result in data theft, malware installation, and further lateral movement within the network. The severity and impact depend on the permissions of the user running hh.exe and the nature of the malicious payload.

## Recommendation

*   Deploy the Sigma rule "Compiled HTML File Spawning Suspicious Processes" to your SIEM to detect instances where `hh.exe` is the parent process of scripting interpreters.
*   Enable Sysmon process creation logging to provide the necessary data for the Sigma rule to function correctly.
*   Monitor process execution chains for unknown processes originating from `hh.exe`, as mentioned in the investigation guide.
*   Implement email filtering and security awareness training to prevent users from opening malicious .chm files delivered via phishing.
*   Block the execution of unsigned or untrusted executables in the environment to reduce the risk of malicious code execution.
*   Use endpoint detection and response (EDR) solutions like Elastic Defend, CrowdStrike, Microsoft Defender XDR, and SentinelOne to detect and respond to malicious activity.
