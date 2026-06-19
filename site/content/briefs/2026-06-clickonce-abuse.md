---
title: 'New Abuse of the ClickOnce Technology: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-06-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's ClickOnce deployment technology, leveraging its user-friendliness, lack of awareness, and built-in update mechanism to deliver and persist malware, bypassing traditional defenses and achieving stealthy execution via legitimate system processes.
date: "2026-06-19T04:54:15Z"
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
  - microsoft
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
  - title: Suspicious dfsvc.exe / rundll32.exe Child Process Creation
    description: Detects when the legitimate ClickOnce service (dfsvc.exe) or rundll32.exe launches suspicious child processes (e.g., script interpreters, common malware tools), indicating a malicious ClickOnce application payload has been executed.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.005
      - T1059
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Creation of Suspicious .appref-ms File for Persistence
    description: Detects the creation of an .appref-ms (ClickOnce application reference) file in a user's Start Menu Programs directory by a process other than the legitimate dfsvc.exe, indicating potential malicious persistence via ClickOnce.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Suspicious Outbound Network Connection from ClickOnce Service (dfsvc.exe)
    description: Detects when the ClickOnce Deployment Framework Service (dfsvc.exe) initiates outbound network connections to unusual or non-standard ports/destinations, potentially indicating malicious C2 communication or data exfiltration from a compromised ClickOnce application.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1041
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

Threat actors are actively leveraging Microsoft's ClickOnce application deployment technology to deliver and persist malware, a trend highlighted by CrowdStrike. This abuse capitalizes on the minimal user interaction required for ClickOnce installations and a general lack of awareness regarding its security implications compared to traditional executable files. Adversaries can convince targets to click a malicious link or open an `.application` file, leading to the deployment of malware without requiring elevated privileges. A significant aspect of this abuse is the `.appref-ms` file, which enables a built-in update mechanism, allowing attackers to push malicious updates and maintain remote access. The malicious payloads execute stealthily within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, complicating detection. This approach bypasses common security controls, offering a powerful and persistent vector for initial access and ongoing control.

## Attack Chain

1.  **Initial Access:** Threat actors leverage social engineering (e.g., phishing) to convince targets to click a malicious link on a webpage or open a weaponized `.application` file.
2.  **Execution (ClickOnce Deployment):** Upon user interaction, the ClickOnce application is downloaded and installed on the system, often without requiring administrative privileges.
3.  **Persistence (Shortcut Creation):** A legitimate `.appref-ms` shortcut file is dropped in the user's Start Menu (%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\), creating a persistent link to the application.
4.  **Malicious Payload Execution:** The ClickOnce application (which now contains the malicious payload) is launched, with its code executing within legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`.
5.  **Stealthy Update Mechanism:** When the user next launches the application via the `.appref-ms` shortcut, the ClickOnce components automatically fetch updates from the attacker-controlled deployment server, delivering new malicious components without further user prompts.
6.  **Command and Control (C2):** The update mechanism provides a reliable method for the attacker to maintain remote access, change C2 addresses, and update their malware as needed.
7.  **Impact:** The updated malware can then perform actions such as lateral movement, data exfiltration, or further compromise of the victim's environment, leveraging the established persistence and stealth.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier to entry for attackers, enabling them to bypass common protection mechanisms like mailbox filtering and traditional executable scrutiny. Attacks can target standard user accounts, which constitute the majority of enterprise endpoints, expanding the potential victim pool. If successful, this can lead to the silent deployment and persistence of malware, granting threat actors continuous remote access and the ability to update their payload. This allows for long-term compromise, facilitating data exfiltration, lateral movement within the network, and establishment of robust command and control channels, all while operating under the guise of legitimate Microsoft processes, making detection challenging.

## Recommendation

*   Enable comprehensive logging for `process_creation`, `file_event`, and `network_connection` on Windows endpoints to capture activity related to ClickOnce processes and files.
*   Deploy the Sigma rules in this brief to your SIEM and tune them for your environment to detect suspicious ClickOnce activity.
*   Regularly review outbound network connections made by `dfsvc.exe` for unusual destinations or high volumes, as detected by the "Suspicious Outbound Network Connection from ClickOnce Service (dfsvc.exe)" rule.
*   Monitor for the creation of `.appref-ms` files in user Start Menu folders by processes other than `dfsvc.exe` using the "Creation of Suspicious .appref-ms File for Persistence" rule.
*   Investigate child processes launched by `dfsvc.exe` and `rundll32.exe` for known malicious binaries or script interpreters, as identified by the "Suspicious dfsvc.exe / rundll32.exe Child Process Creation" rule.
