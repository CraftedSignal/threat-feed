---
title: Potential Protocol Tunneling via Yuze
slug: 2024-01-yuze-tunneling
description: This brief describes the detection of Yuze, an open-source tunneling tool often executed via rundll32 to proxy C2 or pivot traffic within a compromised network.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - tunneling
  - command-and-control
  - windows
products:
  - Yuze
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
references:
  - https://attack.mitre.org/techniques/T1572/
  - https://github.com/P001water/yuze
  - https://www.trendmicro.com/tr_tr/research/26/c/dissecting-a-warlock-attack.html
rules:
  - title: Detect Yuze Execution via Rundll32
    description: Detects the execution of Yuze via rundll32.exe, a common technique for establishing covert tunnels.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1218.011
      - T1572
    data_sources:
      - process_creation
      - windows
  - title: Detect Yuze Tunneling Arguments
    description: Detects specific command line arguments related to Yuze's tunneling capabilities.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Yuze is a lightweight, open-source tunneling tool written in C, designed for intranet penetration testing but often abused by threat actors. It supports both forward and reverse SOCKS5 proxy tunneling, allowing for the creation of covert communication channels. Yuze is commonly executed via `rundll32`, loading `yuze.dll` with the `RunYuze` export. While the project is available on GitHub, its use in conjunction with `rundll32` is a strong indicator of suspicious activity. The tool is effective for bypassing network restrictions and masking malicious traffic, making it a valuable asset for attackers seeking to establish persistent access or exfiltrate sensitive data. Defenders should be vigilant for executions of `rundll32` that load `yuze.dll`, especially when combined with command-line arguments indicative of tunnel creation.

## Attack Chain

1.  The attacker gains initial access to a target Windows system via an exploit or compromised credentials.
2.  The attacker drops `yuze.dll` onto the system, possibly using tools like PowerShell or `certutil.exe`.
3.  The attacker uses `rundll32.exe` to execute the `RunYuze` export within `yuze.dll`.
4.  The `rundll32.exe` command line includes arguments specifying the tunnel type (reverse or forward), along with the IP address and port of the C2 server or pivot point.
5.  `Yuze` establishes a SOCKS5 proxy tunnel to the specified remote endpoint.
6.  The attacker configures their tools to use the newly created tunnel for command and control or lateral movement.
7.  The attacker leverages the tunneled connection to execute commands, transfer files, or access internal resources.
8.  The attacker exfiltrates sensitive data or achieves their objective (e.g., deploying ransomware) while masking their traffic through the established tunnel.

## Impact

Successful deployment of Yuze can enable attackers to bypass network security controls, move laterally within a network, and exfiltrate sensitive data undetected. While the number of victims directly attributed to Yuze usage is not explicitly available, the tool's capabilities can significantly amplify the impact of other attacks, such as ransomware deployment or intellectual property theft. If successful, an attacker can maintain persistence and continue their malicious activity on the victim's network.

## Recommendation

*   Deploy the Sigma rule `Detect Yuze Execution via Rundll32` to detect the execution of Yuze via `rundll32.exe` and monitor process creation events.
*   Enable Sysmon process creation logging to capture command-line arguments for accurate detection of `rundll32.exe` executions (logsource: process_creation).
*   Investigate any `rundll32.exe` process loading `yuze.dll` (rule: `Detect Yuze Execution via Rundll32`) and analyze associated network connections for suspicious activity.
*   Implement network monitoring to detect SOCKS5 traffic originating from internal hosts to identify potential Yuze tunnels.
*   Review and harden endpoint security configurations to prevent unauthorized execution of DLLs via `rundll32.exe`.
