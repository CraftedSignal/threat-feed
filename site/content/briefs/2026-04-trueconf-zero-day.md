---
title: TrueConf Zero-Day Exploitation Leading to Arbitrary Code Execution
slug: 2026-04-trueconf-zero-day
description: Hackers exploited a zero-day vulnerability (CVE-2026-3502) in TrueConf conference servers to execute arbitrary files on connected endpoints, potentially deploying the Havoc C2 framework.
date: "2026-04-02T12:00:00Z"
severities:
  - high
actors:
  - TrueChaos
exploited: true
type: threat
types:
  - threat
tags:
  - trueconf
  - zero-day
  - cve-2026-3502
  - supply-chain attack
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-3502
    cvss: 7.8
    epss: 0.02421
references:
  - https://www.bleepingcomputer.com/news/security/hackers-exploit-trueconf-zero-day-to-push-malicious-software-updates/
iocs:
  - type: file_name
    value: poweriso.exe
  - type: file_name
    value: 7z-x64.dll
  - type: file_name
    value: '%AppData%\Roaming\Adobe\update.7z'
  - type: file_name
    value: iscsiexe.dll
ioc_counts:
  file_name: 4
rules:
  - title: Suspicious TrueConf Update Execution
    description: Detects suspicious processes executing from the TrueConf update directory, indicating a potential malicious update.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.001
    data_sources:
      - process_creation
      - windows
  - title: Potential TrueConf UAC Bypass via iscsicpl.exe
    description: Detects the execution of iscsicpl.exe from a suspicious path, indicating a potential UAC bypass attempt during the TrueChaos campaign.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A threat actor, possibly with Chinese nexus, is exploiting CVE-2026-3502, a zero-day vulnerability in TrueConf versions 8.1.0 through 8.5.2. This vulnerability allows attackers to replace legitimate software updates with malicious variants, leading to arbitrary code execution on connected clients. The attacks, tracked as "TrueChaos" since the beginning of 2026, have targeted government entities in Southeast Asia. TrueConf, a video conferencing platform popular among military forces, government agencies, oil and gas corporations, and air traffic management companies, saw increased adoption during the COVID-19 pandemic. The attacker exploits the lack of integrity check in the update mechanism to deliver malware disguised as a legitimate TrueConf update. A fix was released in version 8.5.3 in March 2026.

## Attack Chain

1.  The attacker gains control of an on-premises TrueConf server.
2.  The attacker replaces the expected update package with a malicious executable file.
3.  The compromised TrueConf server distributes the malicious update to connected clients.
4.  Clients trust the server-provided update without proper validation and download the malicious file.
5.  The malicious file is executed under the guise of a legitimate TrueConf update, initiating DLL sideloading.
6.  Reconnaissance tools such as tasklist and tracert are deployed.
7.  Privilege escalation is attempted using UAC bypass via iscsicpl.exe.
8.  Persistence is established, and network traffic indicates potential deployment of the Havoc C2 framework for further command execution and payload delivery.

## Impact

The successful exploitation of CVE-2026-3502 allows attackers to execute arbitrary code on all TrueConf clients connected to a compromised server. This can lead to widespread malware infections, data theft, and potential compromise of sensitive systems, especially in sectors like government, military, and critical infrastructure that heavily rely on TrueConf for secure communications. The number of affected organizations is potentially high, considering that over 100,000 organizations transitioned to TrueConf during the COVID-19 pandemic.

## Recommendation

*   Upgrade TrueConf servers to version 8.5.3 or later to patch CVE-2026-3502.
*   Monitor for the presence of `poweriso.exe` or `7z-x64.dll` on endpoints, as these are strong indicators of compromise.
*   Investigate systems with suspicious artifacts like `%AppData%\Roaming\Adobe\update.7z` or `iscsiexe.dll`.
*   Deploy the Sigma rule "Suspicious TrueConf Update Execution" to detect malicious updates executing from the TrueConf directory.
*   Monitor network traffic for connections to known Havoc C2 infrastructure.
