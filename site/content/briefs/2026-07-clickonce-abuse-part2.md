---
title: Threat Actors Weaponize ClickOnce Technology for Persistent Malware Delivery
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology, specifically by leveraging `.appref-ms` files for persistence and abusing the built-in update mechanism to stealthily deploy and update malware, enabling remote access and bypassing traditional security controls on Windows systems.
date: "2026-07-07T14:42:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - execution
  - windows
  - malware
  - defense-evasion
vendors:
  - Microsoft
products:
  - Microsoft Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed... Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism... This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce .appref-ms shortcut file in a user's Startup folder, a common technique for establishing persistence.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation for ClickOnce Appref-ms
    description: Detects the creation of a new scheduled task that executes a ClickOnce .appref-ms file, indicating a persistence mechanism via task scheduler.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are actively weaponizing Microsoft's ClickOnce deployment technology, building on existing knowledge and introducing new abuse vectors. This method bypasses common security mechanisms and user scrutiny by leveraging the inherent trust in legitimate Windows features. The attack capitalizes on the user-friendly nature of ClickOnce, which requires minimal interaction to install applications, often flying under the radar compared to executable files. A significant new abuse involves placing `.appref-ms` files, which are shortcuts for ClickOnce applications, into Windows Startup folders or using them with scheduled tasks to achieve persistence. Furthermore, adversaries are exploiting the built-in update mechanism of ClickOnce, compromising application servers or pushing malicious updates to benign applications, thus transforming them into persistent malware without further user consent. This strategy provides a stealthy and persistent foothold, executing within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, making detection challenging for many organizations.

## Attack Chain

1.  **Initial Access / User Execution:** The attacker crafts a malicious ClickOnce application or compromises a legitimate ClickOnce application server. The victim is then tricked into downloading and executing the `.application` file or clicking a link on a malicious webpage that initiates the ClickOnce deployment.
2.  **Execution & Installation:** Upon user interaction, the ClickOnce application is downloaded and executed, leveraging legitimate Windows components like `rundll32.exe` and `dfsvc.exe` to install the initial benign or malicious payload.
3.  **Persistence - `.appref-ms` file deployment:** If configured for offline availability, a shortcut `.appref-ms` file is dropped into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Persistence - Startup Folder:** The attacker manipulates the system to copy the `.appref-ms` file into a user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`), ensuring the malicious ClickOnce application launches upon user logon.
5.  **Persistence - Scheduled Task:** Alternatively, the attacker creates a scheduled task to execute the `.appref-ms` file periodically or upon specific events, maintaining a persistent presence and control over the system.
6.  **Command and Control / Updates:** The attacker uses the ClickOnce built-in update mechanism to push new versions of the malware. When the victim launches the persistent `.appref-ms` shortcut, the system fetches updates from the attacker-controlled server, silently downloading and executing new malicious components or C2 configurations.
7.  **Impact - Remote Access/Data Exfiltration:** The updated malware establishes persistent remote access, enabling further compromise, data exfiltration, or other malicious activities.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access and execute arbitrary code on targeted Windows systems with minimal user interaction and often without requiring elevated privileges. This method bypasses traditional email filtering and executable scrutiny, leading to widespread compromise across various sectors. If successful, organizations face significant risks including initial infection leading to ransomware deployment, data exfiltration, lateral movement within the network, and long-term remote access, often operating stealthily within legitimate system processes. The impact is compounded by the built-in update mechanism, which allows attackers to evolve their malware and maintain control over extended periods.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable Sysmon process-creation and file-creation logging to detect `.appref-ms` files being created in suspicious locations, especially startup folders.
*   Implement strong application whitelisting policies that restrict the execution of unsigned or untrusted ClickOnce applications.
*   Educate users about the dangers of unsolicited application installations and suspicious links, particularly those related to `ClickOnce` or `.application` files.
*   Monitor network traffic for outbound connections to unusual or suspicious domains, especially from processes like `rundll32.exe` or `dfsvc.exe` which could indicate C2 communication from abused ClickOnce applications.
