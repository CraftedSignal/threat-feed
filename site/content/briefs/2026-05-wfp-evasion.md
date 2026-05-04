---
title: Potential Evasion via Windows Filtering Platform Blocking Security Software
slug: 2026-05-wfp-evasion
description: Adversaries may add malicious Windows Filtering Platform (WFP) rules to prevent endpoint security solutions from sending telemetry data, impairing defenses, which this rule detects by identifying multiple WFP block events where the process name is associated with endpoint security software.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows-filtering-platform
  - endpoint-security
vendors:
  - Microsoft
  - Bitdefender
  - VMware Carbon Black
  - Comodo
  - Vectra AI
  - Cybereason
  - Cylance
  - Elastic
  - ESET
  - Broadcom
  - Fortinet
  - Kaspersky
  - Malwarebytes
  - McAfee
  - Qualys
  - SentinelOne
  - Sophos
  - Symantec
  - Trend Micro
  - BeyondTrust
  - CrowdStrike
  - Splunk
  - Tanium
products:
  - Windows Filtering Platform
  - elastic-agent
  - elastic-endpoint
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/dsnezhkov/shutter/tree/main
  - https://github.com/netero1010/EDRSilencer/tree/main
  - https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5152
rules:
  - title: WFP Blocking Security Software - Single Event
    description: Detects a single Windows Filtering Platform block event where the process blocked is associated with endpoint security software, which may indicate an attempt to impair defenses.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - network_connection
      - windows
  - title: WFP Blocking Security Software - Rare Parent Process
    description: Detects Windows Filtering Platform block events where the blocked process is associated with endpoint security software and the parent process is not a standard system process, which may indicate suspicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Windows Filtering Platform (WFP) provides APIs and system services for network filtering and packet processing. Attackers can abuse WFP by creating malicious rules to block endpoint security processes, hindering their ability to send telemetry. This can be achieved by tools like Shutter, EDRSilencer, and Nighthawk. This detection rule identifies patterns of blocked network events linked to security software processes, signaling potential evasion tactics. The rule specifically looks for blocked network events linked to processes associated with known security software, aiming to detect and alert on attempts to disable or modify security tools. This behavior is especially concerning as it allows attackers to operate with reduced visibility.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., via compromised credentials or exploiting a vulnerability).
2.  The attacker escalates privileges to gain administrative rights, necessary to interact with the Windows Filtering Platform.
3.  The attacker uses a tool or script (e.g., leveraging the `netsh` command or custom WFP API calls) to create a new WFP filter.
4.  The WFP filter is configured to block network traffic originating from specific processes associated with endpoint security software (e.g., `elastic-agent.exe`, `sysmon.exe`).
5.  The system begins blocking network communication from the targeted security software.
6.  The attacker executes malicious commands or malware on the system, knowing that security telemetry will be suppressed.
7.  The attacker moves laterally within the network, repeating the WFP filter deployment on other systems to further impair defenses.
8.  The attacker achieves their final objective, such as data exfiltration or ransomware deployment, with reduced risk of detection.

## Impact

A successful attack using WFP to impair defenses can lead to a significant reduction in the effectiveness of endpoint security solutions. This can result in delayed detection of malicious activities, increased dwell time for attackers, and ultimately, a higher likelihood of successful data breaches or ransomware attacks. With endpoint telemetry blocked, organizations may remain unaware of the ongoing compromise until significant damage has occurred. The number of affected systems can vary depending on the attacker's scope and objectives.

## Recommendation

*   Enable and review Windows Audit Filtering Platform Connection and Packet Drop events to populate the logs required for the provided EQL rule (logs-system.security*, logs-windows.forwarded*, winlogbeat-*).
*   Deploy the provided EQL rule to your SIEM to detect suspicious WFP modifications and tune for your environment.
*   Investigate any alerts generated by the EQL rule, focusing on identifying the specific processes being blocked and the source of the WFP rule modifications.
*   Regularly review and audit WFP rules to identify any unauthorized or suspicious entries.
*   Implement strict access controls and monitoring for systems authorized to modify WFP rules.
