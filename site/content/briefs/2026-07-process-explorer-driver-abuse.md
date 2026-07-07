---
title: Malware Abusing Process Explorer Driver for Privilege Escalation
slug: 2026-07-process-explorer-driver-abuse
description: Malware and hack tools are observed creating Sysinternals Process Explorer drivers via non-Sysinternals processes to elevate privileges and bypass security controls on Windows systems.
date: "2026-07-03T14:17:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - driver-abuse
  - privilege-escalation
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Process Explorer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Hack tools or malware may use the Process Explorer driver to elevate privileges
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: ""
    evidence: aukill-edr-killer-malware-abuses-process-explorer-driver/
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: ""
    evidence: runs a service using that driver
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: ""
    evidence: removes it afterwards
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
  - https://github.com/Yaxser/Backstab
  - https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks
  - https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/
rules:
  - title: Process Explorer Driver Creation By Non-Sysinternals Binary
    description: Detects the creation of Sysinternals Process Explorer drivers by processes other than Process Explorer itself, indicating potential privilege escalation or defense evasion attempts by malware or hack tools.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - privilege-escalation
    techniques:
      - T1068
      - T1543.003
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Adversaries are leveraging a technique that involves the abuse of legitimate Sysinternals Process Explorer drivers (`PROCEXP*.sys`) to gain elevated privileges on Windows systems. This method entails dropping the driver to disk via a malicious process that is not the official Process Explorer utility itself. Once dropped, the adversary can create a service using this driver, which then allows their code to operate with system-level privileges. This technique is often short-lived, with the driver being removed shortly after privilege escalation is achieved, making detection challenging. This allows attackers to bypass security solutions like EDRs and perform actions that require high integrity, such as terminating security processes or modifying critical system configurations.

## Attack Chain

1.  **Initial Compromise**: An adversary gains initial access to a Windows system through an unspecified mechanism, such as exploiting a vulnerability or via a phishing attack.
2.  **Execution**: Malware or hack tools are executed on the compromised endpoint, initiating the malicious activity.
3.  **Payload Dropping**: The malicious process (not `procexp.exe` or its variants) drops a legitimate Sysinternals Process Explorer driver file (e.g., `PROCEXP64.sys`) to a temporary location on the disk.
4.  **Service Creation**: The malware programmatically creates a new Windows service, configured to load and execute the dropped `PROCEXP*.sys` driver.
5.  **Privilege Escalation**: The newly created service is started, leveraging the signed Process Explorer driver to achieve system-level privileges, allowing the attacker to bypass user access controls and potentially EDR solutions.
6.  **Post-Exploitation & Cleanup**: After achieving the desired objective (e.g., disabling security software, system modifications), the malware removes the dropped driver file and may delete the associated service to cover its tracks and evade forensic analysis.

## Impact

The successful exploitation of this technique grants attackers system-level privileges, enabling them to completely compromise the affected Windows endpoint. This can lead to the termination or disabling of security software (such as EDR agents), exfiltration of sensitive data, deployment of ransomware, or establishment of persistent access. The impact can extend to full network compromise if the elevated privileges are used to pivot to other systems or compromise domain controllers. Specific instances have been observed where this technique contributed to EDR bypasses, allowing malware like Aukill to operate undetected.

## Recommendation

*   Deploy the Sigma rule 'Process Explorer Driver Creation By Non-Sysinternals Binary' to your SIEM and tune for your environment.
*   Enable `file_event` logging (e.g., Sysmon Event ID 11 for FileCreate) on all Windows endpoints to ensure the detection rule has the necessary telemetry.
*   Implement application whitelisting solutions to prevent unauthorized executables from running on endpoints.
