---
title: New Abuse of ClickOnce Technology for Persistent Access and Malware Delivery
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology to gain initial access, achieve persistence, and evade defenses by luring users into installing seemingly benign applications, then leveraging the built-in update mechanism and `.appref-ms` files for malware delivery and sustained remote access without requiring elevated privileges.
date: "2026-07-06T06:39:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - defense-evasion
  - initial-access
  - execution
  - malware
  - windows
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
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism. ... This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms File Creation in Startup Folder
    description: Detects the creation or modification of .appref-ms files within user Startup folders, a known persistence technique for ClickOnce abuse.
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
  - title: Detect Scheduled Task Creation for ClickOnce .appref-ms Files
    description: Detects the creation of new scheduled tasks (`schtasks.exe`) that are configured to execute ClickOnce .appref-ms files, indicating a persistence mechanism.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are increasingly weaponizing Microsoft's ClickOnce technology, as highlighted by CrowdStrike in June 2026, building upon previous research into `.appref-ms` abuse. This abuse focuses on exploiting the user-friendly deployment process, which requires minimal user interaction and no elevated privileges, allowing attackers to bypass traditional security mechanisms like email filtering and avoid scrutiny typically applied to `.exe` files. Adversaries leverage the legitimate ClickOnce infrastructure, including its built-in updating mechanism and execution within trusted Microsoft processes such (`rundll32.exe`, `dfsvc.exe`), to discreetly deploy, persist, and update malicious payloads. This strategy provides a stealthy and reliable method for maintaining remote access, facilitating lateral movement, and ultimately achieving objectives such as data exfiltration or system control, posing a significant challenge for defenders unaware of these attack vectors.

## Attack Chain

1.  **Initial Access - Lure User**: Threat actors craft a malicious ClickOnce application, often hosted on a controlled server, and lure users (e.g., via phishing, malicious websites) to click a link or button to initiate its deployment.
2.  **Execution - User Installation**: The user interacts minimally with a legitimate-looking ClickOnce installation prompt, allowing the application to deploy without requiring administrative privileges, bypassing typical `.exe` scrutiny.
3.  **Deployment & Initial Persistence**: The malicious ClickOnce application is installed, dropping a `.appref-ms` shortcut in `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\` to enable offline access and provide an initial persistence mechanism via the Start Menu.
4.  **Persistence - Startup Folder**: For more robust persistence, the attacker places the `.appref-ms` file directly into the user's Startup folder, ensuring the malicious application launches automatically upon system reboot or user login.
5.  **Persistence - Scheduled Task**: Alternatively, the attacker creates a scheduled task using `schtasks.exe` to execute the `.appref-ms` file at regular intervals or under specific conditions, maintaining a persistent foothold.
6.  **Defense Evasion & Execution**: The malicious ClickOnce payload executes within legitimate Microsoft process trees, such as `dfsvc.exe` (the ClickOnce deployment service) or `rundll32.exe`, making it difficult to distinguish from benign activity.
7.  **Command and Control / Updates**: Attackers utilize the legitimate ClickOnce built-in update mechanism to push updated malicious payloads, changing C2 addresses, deploying new malware components, or adapting to detected defenses.
8.  **Impact - Continued Compromise**: The updated malicious payload is downloaded and executed silently without user authorization, leading to sustained remote access, potential lateral movement within the network, and the achievement of the attacker's final objective (e.g., data exfiltration, ransomware deployment).

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access to target systems, bypass common initial access defenses, and maintain stealthy operations within legitimate process environments. If successful, this can lead to unauthorized data access and exfiltration, deployment of additional malware (e.g., ransomware, infostealers), and complete system or network compromise. The ease of deployment without elevated privileges significantly broadens the target scope to include standard user accounts, which comprise the majority of enterprise endpoints. The silent update mechanism ensures attackers can evolve their payloads, making long-term detection and eradication challenging.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable Sysmon file creation/modification logging for user-specific `Startup` folders (`C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) to activate the rule detecting `.appref-ms` files.
*   Monitor `process_creation` events for `schtasks.exe` executions that involve `.appref-ms` files as arguments.
*   Educate users about the risks of installing untrusted applications, even those that appear to be from legitimate sources or require minimal interaction.
*   Implement application whitelisting or strict controls to prevent unauthorized ClickOnce application deployments where feasible.
