---
title: Execution of a Downloaded Windows Script
slug: 2024-01-downloaded-script-execution
description: This rule identifies the creation and subsequent execution of a Windows script downloaded from the internet, a technique used by adversaries for initial access and execution on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - windows
  - scripting
  - threat-detection
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_windows_script_from_internet.toml
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1218/
rules:
  - title: Downloaded Script Execution via WScript/CScript
    description: Detects the execution of a script (e.g., .js, .vbs) downloaded from the internet via wscript.exe or cscript.exe
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Downloaded Script Execution via PowerShell
    description: Detects the execution of a PowerShell script (.ps1) downloaded from the internet.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Downloaded Script Execution via MSHTA
    description: Detects the execution of a script downloaded from the internet via mshta.exe
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies a common attack vector where adversaries download and execute malicious scripts on Windows systems. The rule focuses on detecting scripts (e.g., .js, .vbs, .ps1, .msi) that originate from internet sources (identified by the presence of `file.origin_url` or `file.origin_referrer_url` ) and are subsequently executed using scripting utilities. The rule specifically looks for file creations by web browsers and archive utilities (chrome.exe, msedge.exe, winrar.exe, 7zFM.exe, etc.) followed by execution of script interpreters (wscript.exe, cscript.exe, powershell.exe, mshta.exe, msiexec.exe) with command-line arguments referencing the downloaded script. This activity is often indicative of malicious intent, as legitimate scripts are typically sourced from trusted internal repositories or local file systems, and not directly downloaded and executed. The rule aims to detect suspicious parent-child process relationships (e.g., browser spawning a script interpreter) and identify potential initial access or execution attempts. The rule requires Elastic Defend and a minimum Elastic Stack version of 9.2.0.

## Attack Chain

1. A user browses to a malicious website or opens a compromised email containing a link.
2. The user clicks the link, which initiates a download of a malicious script file (e.g., .js, .vbs, .ps1, .msi) via a web browser (chrome.exe, msedge.exe).
3. The browser saves the downloaded script file to the user's Downloads folder.
4. The user, either intentionally or through social engineering, executes the downloaded script.
5. Windows executes the script using a scripting utility like wscript.exe, cscript.exe, powershell.exe, mshta.exe, or msiexec.exe.
6. The scripting utility executes the malicious code within the script, potentially establishing persistence, downloading additional payloads, or performing reconnaissance.
7. The script may attempt to elevate privileges or bypass security controls to gain further access to the system.
8. The attacker achieves their objective, such as deploying ransomware, stealing sensitive data, or establishing a remote access backdoor.

## Impact

A successful attack can lead to a variety of negative outcomes, including malware infection, data theft, and system compromise. If the downloaded script is malicious, it can allow attackers to gain a foothold on the system, escalate privileges, and move laterally within the network. This can result in significant financial losses, reputational damage, and disruption of business operations. The number of victims and affected sectors can vary depending on the scale and scope of the attack.

## Recommendation

*   Deploy the Elastic Defend integration to collect necessary event data, as described in the [setup instructions](https://ela.st/install-elastic-defend).
*   Deploy the Sigma rule "Execution of a Downloaded Windows Script" to your SIEM and tune for your environment to detect the execution of downloaded scripts.
*   Enable Sysmon process creation logging and file creation events to provide the necessary data for the Sigma rules to function correctly.
*   Implement application whitelisting to restrict the execution of unauthorized scripts and scripting utilities to reduce the risk of similar threats in the future, as mentioned in the "Response and remediation" section.
*   Block known malicious domains and URLs identified in related threat intelligence feeds to prevent users from downloading malicious scripts in the first place.
*   Educate users about the dangers of downloading and executing untrusted scripts from the internet, as this is a common initial access vector.
