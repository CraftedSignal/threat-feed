---
title: First Time Seen Driver Loaded
slug: 2024-01-first-time-seen-driver-loaded
description: The rule identifies the load of previously unseen drivers, which may indicate attackers exploiting vulnerable drivers for privilege escalation and persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Microsoft
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.elastic.co/kr/security-labs/stopping-vulnerable-driver-attacks
rules:
  - title: Driver Loaded with New File Name and Signature
    description: Detects the loading of a driver with a previously unseen original file name and signature, indicating potential exploitation of vulnerable drivers for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1547.006
    data_sources:
      - process_creation
      - windows
  - title: Detect Unsigned Driver Load
    description: Detects the loading of an unsigned driver which can indicate a bypassing of security controls.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1547.006
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This rule identifies the loading of a driver with a unique original file name and signature values observed for the first time within the last 30 days. The intent is to provide a baseline of driver installations within an environment and highlight potentially suspicious activity. Attackers often exploit vulnerable drivers to execute code in the kernel, granting them high levels of control. These drivers can be leveraged to tamper with security software, bypass protections, escalate privileges, establish persistent access, and disable operating system monitoring features. Elastic Security Labs research highlights how adversaries conduct these actions before executing objectives like ransomware deployment.

## Attack Chain

1.  An attacker gains initial access to a system, potentially through phishing or exploiting a software vulnerability.
2.  The attacker identifies a vulnerable, signed driver that can be leveraged for privilege escalation.
3.  The attacker obtains or crafts a malicious driver designed to exploit the identified vulnerable driver.
4.  The attacker loads the malicious driver onto the system, potentially bypassing security controls.
5.  The vulnerable driver is exploited, allowing the attacker to execute arbitrary code in the kernel.
6.  The attacker leverages their kernel-level access to disable security software or bypass operating system protections.
7.  The attacker escalates privileges to gain SYSTEM level access.
8.  The attacker establishes persistence by creating a new service or modifying existing system processes.

## Impact

A successful attack using a vulnerable driver can lead to complete system compromise. Attackers can disable security controls, steal sensitive data, deploy ransomware, or establish long-term persistence. The rule aims to identify these attempts early, before significant damage occurs. While the exact number of victims and sectors targeted are unknown, the impact can be widespread due to the high privilege level gained.

## Recommendation

*   Deploy the Sigma rule `Driver Loaded with New File Name and Signature` to your SIEM and tune for your environment.
*   Use Osquery to investigate drivers loaded into the system using the queries provided in the overview: `$osquery_0` and `$osquery_1`.
*   Enable Elastic Defend to ensure proper data collection and enrichment as required by this rule.
*   Investigate the digital signature and file creation/modification timestamps of identified drivers to identify suspicious characteristics, using the `dll.hash.sha256` value to check reputation on VirusTotal and other threat intelligence platforms.
*   Ensure Driver Signature Enforcement is enabled on the systems.
