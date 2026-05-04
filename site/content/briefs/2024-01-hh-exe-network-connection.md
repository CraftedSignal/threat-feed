---
title: Network Connection via Compiled HTML File
slug: 2024-01-hh-exe-network-connection
description: This rule detects network connections initiated by hh.exe, the HTML Help executable, which may indicate the execution of malicious code embedded in compiled HTML files (.chm) to deliver malicious payloads, bypass security controls, and gain initial access via social engineering.
date: "2024-01-03T17:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - defense-evasion
  - command-and-control
  - malicious-file
  - html-help
vendors:
  - Microsoft
products:
  - HTML Help
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/tactics/TA0002/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/001/
  - https://attack.mitre.org/tactics/TA0005/
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/tactics/TA0011/
rules:
  - title: Network Connection via Compiled HTML File
    description: Detects network connections initiated by hh.exe, the HTML Help executable, excluding connections to private IP ranges.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1071
      - T1218.001
    data_sources:
      - network_connection
      - windows
  - title: HH.exe spawning child processes
    description: Detects when hh.exe spawns a child process, potentially indicating the execution of a downloaded payload.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adversaries may conceal malicious code in a compiled HTML file (.chm) and deliver it to a victim for execution. CHM content is loaded by the HTML Help executable program (hh.exe). Attackers can use CHM files to proxy the execution of malicious payloads via a signed binary to bypass security controls, and also to gain initial access to environments via social engineering methods. This rule identifies network connections done by hh.exe, which can potentially indicate abuse to download malicious files or tooling, or masquerading. The detection logic focuses on network connections originating from hh.exe to external IPs, excluding private or reserved IP ranges.

## Attack Chain

1. The user receives a compiled HTML file (.chm), often through social engineering tactics such as phishing.
2. The user opens the .chm file, which is then executed by the HTML Help executable (hh.exe).
3. The hh.exe process loads and renders the HTML content within the .chm file.
4. Embedded within the HTML content is malicious JavaScript or other scripting code.
5. The malicious script executes, initiating a network connection via hh.exe to an external server.
6. The external server hosts a malicious payload, such as a reverse shell or an executable file.
7. Hh.exe downloads the malicious payload to the victim's machine.
8. The downloaded payload is executed, granting the attacker initial access or performing other malicious actions like data exfiltration or lateral movement.

## Impact

A successful attack can lead to initial access to a victim's system, potentially bypassing security controls through a signed Microsoft binary. This can result in the download and execution of arbitrary payloads, leading to data exfiltration, lateral movement within the network, or installation of malware. The exploitation can spread rapidly through social engineering, affecting multiple users within an organization. While the severity is rated as medium, the potential for escalation to a critical compromise is high if the attacker gains a foothold in the environment.

## Recommendation

*   Enable process and network monitoring on Windows endpoints, focusing on hh.exe activity (Data Source: Elastic Defend, Sysmon, SentinelOne).
*   Deploy the Sigma rule `Network Connection via Compiled HTML File` to your SIEM and tune for your environment to detect suspicious network connections initiated by hh.exe.
*   Monitor for hh.exe spawning child processes, which could indicate the execution of downloaded payloads. Create a Sigma rule to detect such events.
*   Implement network segmentation to limit the impact of a compromised host and restrict lateral movement.
*   Conduct regular security awareness training to educate users about the risks of opening unsolicited .chm files.
*   Inspect the digital signatures of hh.exe and other system binaries to ensure their integrity and authenticity.
