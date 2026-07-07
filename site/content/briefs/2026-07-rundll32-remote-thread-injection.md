---
title: Rundll32 Remote Thread Injection by Malware
slug: 2026-07-rundll32-remote-thread-injection
description: This brief details the use of rundll32.exe to create remote threads into other processes, a technique observed with malware like IcedID, enabling defense evasion, arbitrary code execution, privilege escalation, and data theft on Windows endpoints.
date: "2026-07-06T10:08:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rundll32
  - remote-thread-injection
  - icedid
  - defense-evasion
  - code-injection
  - windows
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: The following analytic detects the creation of a remote thread by rundll32.exe into another process. It leverages Sysmon EventCode 8 logs, specifically monitoring SourceImage and TargetImage fields. This activity is significant as it is a common technique used by malware, such as IcedID, to execute malicious code within legitimate processes, aiding in defense evasion and data theft.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/rundll32_create_remote_thread_to_a_process.yml
  - https://www.joesandbox.com/analysis/380662/0/html
rules:
  - title: Detect Rundll32 Create Remote Thread to Other Process
    description: Detects rundll32.exe creating a remote thread in another process, a technique often used by malware like IcedID for code injection and defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1055
      - T1055.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat brief focuses on the malicious use of `rundll32.exe` to perform remote thread injection, a sophisticated technique employed by various malware families, notably IcedID. This activity involves a legitimate `rundll32.exe` process creating a thread within another, often legitimate, process, allowing the attacker's code to execute discreetly within the target's memory space. This method significantly aids in defense evasion by blending malicious operations with normal system processes. Detection relies on monitoring Sysmon EventCode 8 logs, which specifically track `CreateRemoteThread` operations. If successfully exploited, this technique grants attackers the ability to execute arbitrary code, escalate privileges, maintain persistence, and ultimately exfiltrate sensitive data from compromised Windows endpoints, making it a critical concern for defenders.

## Attack Chain

1.  **Initial Compromise**: A malware payload, such as IcedID, is delivered and executed on a victim's Windows system (e.g., via phishing or exploit kit).
2.  **Malware Execution**: The malware initiates `rundll32.exe`, often with specific parameters to load a malicious DLL.
3.  **Process Target Identification**: `rundll32.exe`, under malware control, identifies a suitable target process (e.g., a common `*.exe` application like a web browser or system utility) for code injection.
4.  **Remote Thread Creation**: `rundll32.exe` leverages the `CreateRemoteThread` API to create a new thread within the address space of the identified target process.
5.  **Malicious Code Injection & Execution**: The newly created remote thread then executes malicious code or a loaded DLL payload within the context of the legitimate target process.
6.  **Defense Evasion & Privilege Escalation**: By executing within a legitimate process, the malware evades detection by security tools and potentially inherits the privileges of the target process, facilitating further malicious activities.
7.  **Command and Control / Data Exfiltration**: The injected code establishes command-and-control communication, performs data exfiltration, or initiates further stages of the attack, such as deploying ransomware or additional tools.

## Impact

The observed impact of this technique includes significant operational disruption and data compromise. When `rundll32.exe` is used for remote thread injection, attackers gain the ability to execute arbitrary code with elevated privileges, bypassing many standard security controls. This can lead to complete system takeover, exfiltration of sensitive organizational data, deployment of ransomware (as seen with IcedID variants), and establishment of persistent access. The defense evasion capabilities of this technique make it particularly dangerous, allowing malware to operate unnoticed for extended periods, potentially affecting a broad range of systems across various industry sectors without specific targeting limitations.

## Recommendation

*   Deploy the Sigma rule "Detect Rundll32 Create Remote Thread to Other Process" to your SIEM and tune for your environment.
*   Ensure Sysmon is deployed on all Windows endpoints with Event ID 8 logging enabled for `CreateRemoteThread` events.
*   Monitor `SourceImage` and `TargetImage` fields within Sysmon Event ID 8 logs for `rundll32.exe` performing remote thread creation.
*   Investigate any instances of `rundll32.exe` initiating `CreateRemoteThread` events as this is a high-fidelity indicator of malicious activity.
