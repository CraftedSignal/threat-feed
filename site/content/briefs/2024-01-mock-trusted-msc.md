---
title: Malicious MSC File Creation in Mock Trusted Directory
slug: 2024-01-mock-trusted-msc
description: The creation of MSC files within a 'C:\Windows \System32' directory can be exploited to execute malicious files due to path parsing vulnerabilities in Windows, potentially leading to privilege escalation, persistence, and defense evasion.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Splunk
  - Fortinet
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://www.fortinet.com/blog/threat-research/fickle-stealer-distributed-via-multiple-attack-chain
rules:
  - title: Detect MSC File Creation in Mock Trusted Directory
    description: Detects the creation of MSC files within a 'C:\Windows \System32' directory, indicative of a potential execution flow hijack.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1218.014
    data_sources:
      - file_event
      - windows
  - title: Detect Process Launching MSC File from Mock Trusted Directory
    description: Detects processes launching MSC files from directories containing spaces within the Windows system directory, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1218.014
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The creation of specially crafted MSC (Microsoft Management Console) files within directories that mimic trusted Windows system directories, specifically including a space in the path such as "C:\Windows \System32", can lead to execution of arbitrary code. This is due to the way Windows parses file paths, where the space character can be misinterpreted, causing the system to execute a malicious file located in the altered path instead of the legitimate Windows component. This technique can be used by attackers to bypass security controls, escalate privileges, and establish persistence on the compromised system. This technique is related to the Fickle Stealer attack chain.

## Attack Chain

1. An attacker gains initial access to the system (e.g., through phishing or exploiting a software vulnerability).
2. The attacker creates a directory mimicking a trusted Windows directory but containing a space, such as "C:\Windows \System32".
3. The attacker crafts a malicious MSC file and places it within the newly created directory, naming it similarly to a legitimate Windows MSC file (e.g., `services.msc`).
4. The attacker uses a method to trigger the execution of the malicious MSC file. This might involve tricking a user into opening the file or using a script to call the file.
5. When the system attempts to execute the intended legitimate MSC file, it is redirected to the malicious file due to the path parsing issue.
6. The malicious MSC file executes, performing actions such as installing malware, modifying system settings, or establishing persistence.
7. The attacker can then leverage the compromised system for further malicious activities, such as data theft or lateral movement.

## Impact

Successful exploitation allows attackers to bypass security measures and execute arbitrary code with elevated privileges. This can lead to complete system compromise, data theft, and the installation of persistent backdoors. While specific victim numbers are not available, organizations relying on standard Windows security configurations are vulnerable. This can have severe consequences for confidentiality, integrity, and availability of affected systems.

## Recommendation

*   Enable Sysmon Event ID 11 (FileCreate) to monitor file creation events, which is the `data_source` for the provided detection.
*   Deploy the Sigma rule `Detect MSC File Creation in Mock Trusted Directory` to your SIEM and tune for your environment.
*   Investigate any file creation events in directories resembling "C:\Windows \System32" with space, focusing on MSC files to identify and remediate potential exploitation.
*   Review and restrict user permissions to prevent unauthorized file creation in sensitive system directories.
*   Consider using application control solutions to whitelist approved executables and prevent the execution of unauthorized MSC files.
