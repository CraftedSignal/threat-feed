---
title: Threat Actors Abuse Microsoft ClickOnce for Stealthy Malware Delivery and Persistence
slug: 2026-06-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce deployment technology to deliver and persist malware by exploiting its user-friendly installation, lack of user awareness, and built-in update mechanism, enabling stealthy execution within legitimate Windows processes and bypassing traditional security controls to maintain remote access and facilitate further malicious activities.
date: "2026-06-21T07:02:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - delivery
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Suspicious Child Process of ClickOnce Deployment Service
    description: Detects `dfsvc.exe`, the ClickOnce Deployment Services Client, spawning suspicious child processes like common scripting or shell interpreters, which can indicate malicious payload execution or C2 activity leveraging legitimate ClickOnce processes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Rundll32.exe Activity from ClickOnce Context
    description: Detects `rundll32.exe`, when launched in a ClickOnce context (e.g., as a child of `dfsvc.exe`), executing suspicious commands or loading unusual DLLs, indicating potential malicious payload execution or defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are increasingly weaponizing Microsoft's ClickOnce technology to facilitate the stealthy delivery and persistence of malware on target systems. This technique leverages ClickOnce's features, such as simplified user interaction for installation (requiring only one or two clicks), the ability to deploy applications without elevated administrative privileges, and its built-in update mechanism. Attackers exploit a general lack of awareness among users and security tools regarding `.application` files, allowing malicious payloads to bypass typical email filtering and security scrutiny. The legitimate nature of ClickOnce execution, often involving processes like `dfsvc.exe` and `rundll32.exe`, provides a powerful defense evasion mechanism. This approach enables adversaries to establish persistent remote access, update their malware, and conduct further malicious activities without raising immediate suspicion.

## Attack Chain

1.  **Initial Access / User Execution**: Threat actor convinces the target user to click a malicious link or button, often distributed via phishing, leading to the download of a `.application` file.
2.  **Deployment**: The user interaction triggers the ClickOnce deployment mechanism, installing the application without requiring administrator privileges.
3.  **Payload Execution (Initial)**: The initial malicious payload executes as part of the ClickOnce application deployment, often within legitimate Microsoft process trees like `dfsvc.exe` or `rundll32.exe`.
4.  **Persistence Establishment**: A shortcut file (`.appref-ms`) is dropped into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) by the ClickOnce mechanism, configured to automatically check for updates.
5.  **Malicious Update**: The threat actor, controlling the deployment server, pushes a malicious update for the ClickOnce application.
6.  **Update Execution / Code Download**: The next time the user launches the application via the `.appref-ms` shortcut, the ClickOnce components fetch the malicious update from the server.
7.  **Payload Execution (Updated)**: The newly downloaded malicious components are executed without further user prompts, enabling remote access, C2 communication, lateral movement, or other attacker objectives.
8.  **Impact**: The attacker maintains persistent access, updates their tooling, exfiltrates data, or deploys additional malware (e.g., ransomware) leveraging the established foothold.

## Impact

The abuse of ClickOnce technology allows threat actors to establish a stealthy and persistent presence within victim environments. By executing within legitimate Microsoft processes, the malicious activity can evade traditional security controls that might scrutinize known malware executables. Organizations across various sectors are vulnerable, as this technique exploits a fundamental, legitimate Windows feature. Successful attacks can lead to sustained remote access, data exfiltration, deployment of ransomware, and lateral movement across the network, ultimately compromising the integrity and confidentiality of critical systems and data. The widespread nature of Windows environments makes this a significant threat vector.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically prioritizing `process_creation` events involving `dfsvc.exe` and `rundll32.exe`.
*   Enable Sysmon `process_creation` and `file_event` logging to activate the rules above and gain visibility into ClickOnce application behavior.
*   Implement application control policies to restrict the execution of unsigned or untrusted ClickOnce applications, particularly those originating from untrusted internet sources.
*   Monitor network connections originating from `dfsvc.exe` or `rundll32.exe` to unexpected external IP addresses or non-standard ports.
*   Educate users about the risks of clicking on untrusted links or downloading software from unverified sources, even if it appears to be a legitimate application installer.
