---
title: Windows Defender Evasion via Protected Process Light (PPL) Manipulation
slug: 2024-01-03-ppl-defender-evasion
description: An attacker can potentially evade Windows Defender by manipulating Protected Process Light (PPL) attributes, allowing malicious processes to operate with elevated privileges and avoid security scans.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ppl
  - windows-defender
  - evasion
vendors:
  - Microsoft
products:
  - Windows
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Windows Event Logs'
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055.001
    technique_name: 'Process Injection: Dynamic-link Library Injection'
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rat4id/demonstrating-windows-defender-evasion-via-ppl/
  - https://medium.com/@s12deff/demonstrating-windows-defender-evasion-via-ppl-manipulation-8767f1ee7ad9
rules:
  - title: Detect Process Modification of PPL Attributes
    description: Detects attempts to modify PPL attributes of running processes, potentially indicating an evasion attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Injection into Protected Processes
    description: Detects process injection attempts into processes with PPL protection levels, which could signify PPL bypass techniques.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1055.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The technique described involves manipulating the Protected Process Light (PPL) mechanism in Windows to evade Windows Defender. PPL is a security feature designed to protect critical system processes. However, by manipulating PPL attributes, an attacker can potentially elevate the privileges of a malicious process, allowing it to bypass security checks and operate undetected. This can lead to arbitrary code execution and system compromise. The reported research, published on Medium, demonstrates a proof-of-concept of this evasion technique, highlighting the potential vulnerability in Windows security architecture and the need for enhanced detection and mitigation strategies.

## Attack Chain

1.  Attacker gains initial access to the system (e.g., via phishing or exploiting a software vulnerability).
2.  Attacker elevates privileges to SeDebugPrivilege to allow manipulation of protected processes.
3.  Attacker identifies a target process to inject into (e.g., a legitimate, signed process with a PPL level).
4.  Attacker modifies the PPL attributes of the target process to a less protected level or disables PPL altogether. This may involve direct memory manipulation or other techniques to bypass security checks.
5.  Attacker injects malicious code into the now-vulnerable process. This injected code inherits the process's (modified) PPL attributes.
6.  The injected code executes, bypassing Windows Defender scans due to the manipulated PPL, and performs malicious activities like downloading additional payloads or exfiltrating data.
7.  The attacker establishes persistence through the compromised process or other means.

## Impact

Successful exploitation allows attackers to execute arbitrary code with elevated privileges, effectively bypassing Windows Defender. This can lead to complete system compromise, data theft, or deployment of ransomware. While the number of victims and targeted sectors are unknown, the potential impact is significant given the widespread use of Windows Defender in enterprise environments. Successful evasion allows malware to operate undetected, causing significant damage before discovery.
