---
title: Remote File Download via Script Interpreter
slug: 2024-01-28-remote-file-copy-scripts
description: Attackers are using Windows script interpreters (cscript.exe or wscript.exe) to download executable files from remote locations to deliver second-stage payloads or download tools.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - execution
  - windows
  - script_interpreter
vendors:
  - Microsoft
products:
  - Windows Script Host
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_remote_file_copy_scripts.toml
rules:
  - title: Remote File Download via Script Interpreter - File Creation
    description: Detects the creation of executable files after network activity from cscript.exe or wscript.exe, indicating a remote file download.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.005
      - T1059.007
      - T1105
    data_sources:
      - file_event
      - windows
  - title: Remote File Download via Script Interpreter - Network Connection
    description: Detects network connections from cscript.exe or wscript.exe, which could indicate a remote file download.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1105
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Attackers commonly use Windows Script Host (WSH) scripts as an initial access method or to download tools and utilities. This involves using built-in Windows script interpreters like `cscript.exe` or `wscript.exe` to download executable files from remote destinations. This behavior is significant because it allows attackers to bypass traditional defenses and establish a foothold in the system or download further tools. Defenders should monitor for suspicious network connections initiated by script interpreters followed by the creation of executable files on the system.

## Attack Chain

1. An attacker gains initial access to a Windows system (delivery mechanism not specified in source).
2. The attacker executes a script using `cscript.exe` or `wscript.exe`.
3. The script interpreter makes an outbound network connection to a remote server.
4. The remote server hosts a malicious executable file (e.g., .exe, .dll).
5. The script downloads the malicious executable to the compromised system.
6. The downloaded file is saved to disk.
7. The attacker executes the downloaded malicious file to establish persistence or further compromise the system.
8. The attacker performs additional actions, such as lateral movement or data exfiltration (not detailed in the source).

## Impact

Successful exploitation can lead to the installation of malware, unauthorized access to sensitive data, and further compromise of the affected system. This can result in data breaches, financial losses, and reputational damage. The source does not contain specific victim numbers or sectors targeted.

## Recommendation

*   Deploy the Sigma rule "Remote File Download via Script Interpreter - File Creation" to your SIEM to detect the creation of executable files after network activity from `cscript.exe` or `wscript.exe`.
*   Deploy the Sigma rule "Remote File Download via Script Interpreter - Network Connection" to detect network connections from `cscript.exe` or `wscript.exe`.
*   Enable Sysmon Event ID 3 (Network Connection) and Event ID 11 (File Create) for enhanced visibility into network and file activity related to script interpreters.
