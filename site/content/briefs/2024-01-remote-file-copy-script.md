---
title: Remote File Download via Script Interpreter
slug: 2024-01-remote-file-copy-script
description: The rule identifies built-in Windows script interpreters, specifically cscript.exe or wscript.exe, being used to download an executable file from a remote destination, often employed by attackers for initial access or to deploy secondary payloads.
date: "2024-01-02T17:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command_and_control
  - execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_remote_file_copy_scripts.toml
rules:
  - title: Detect Remote File Download via CScript or WScript
    description: Detects the execution of cscript.exe or wscript.exe followed by a network connection and file creation of a potentially malicious executable.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.005
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Remote File Download by Script Interpreter (EQL)
    description: Identifies when a script interpreter (cscript.exe or wscript.exe) downloads an executable file from a remote destination using EQL.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.005
      - T1105
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Attackers frequently leverage Windows Script Host (WSH) scripts, such as those executed by `cscript.exe` and `wscript.exe`, to facilitate their operations within a compromised environment. These scripts can act as initial access vectors, serving as droppers for subsequent payloads, or they can be used to download tools and utilities necessary for lateral movement and privilege escalation. This activity typically begins post-exploitation, as the attacker seeks to establish a persistent foothold or expand their control within the network. This detection focuses on identifying instances where these script interpreters are used to retrieve executable files (e.g., .exe, .dll) from remote locations. The rule specifically targets the anomalous use of `cscript.exe` and `wscript.exe` to download executable files, distinguishing it from legitimate uses of these tools.

## Attack Chain

1. An attacker gains initial access to a Windows system through an external vector.
2. The attacker executes `cscript.exe` or `wscript.exe`.
3. The script interpreter initiates a network connection to a remote server over HTTP/HTTPS, avoiding DNS resolution for obfuscation.
4. The script downloads a malicious executable file (e.g., .exe, .dll, .ps1) to the compromised host.
5. The downloaded file is saved to disk, often in a temporary directory or a location accessible to the attacker.
6. The script may then execute the downloaded file, initiating further malicious activity.
7. The executed payload establishes persistence, moves laterally, or exfiltrates data.
8. The attacker achieves their objective, such as data theft or system compromise.

## Impact

Successful exploitation can lead to the installation of malware, backdoors, or other malicious tools on the compromised system. This can enable attackers to gain persistent access, steal sensitive data, or disrupt business operations. The use of scripting engines like `cscript.exe` and `wscript.exe` allows attackers to bypass traditional security controls that focus on executable files, making detection more challenging. Organizations that fail to detect and respond to this activity risk significant financial and reputational damage.

## Recommendation

*   Enable and monitor Windows event logs, specifically Sysmon, to capture process creation, network connections, and file creation events, as indicated by the `logs-windows.sysmon_operational-*` index.
*   Implement the provided Sigma rule to detect the execution of `cscript.exe` or `wscript.exe` followed by the creation of executable files, tuning for your specific environment.
*   Enrich network event logs with threat intelligence to identify connections to known malicious IPs or domains, correlating with network connections initiated by `cscript.exe` or `wscript.exe`.
*   Monitor file creation events for executable files downloaded to suspicious locations, such as temporary directories or user profiles, in conjunction with process execution by `cscript.exe` or `wscript.exe`.
