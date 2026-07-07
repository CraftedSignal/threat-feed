---
title: New Abuse of ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology to simplify malware delivery, bypass traditional security defenses, gain persistence through `.appref-ms` files, and stealthily update payloads, leveraging legitimate processes and user unawareness to maintain long-term access on targeted Windows endpoints.
date: "2026-07-04T08:07:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - malware
  - delivery
  - windows
  - endpoint-security
vendors:
  - Microsoft
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. [...] All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run without the user realizing the application has changed.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce dfsvc.exe Spawning Unusual Child Processes
    description: Detects potentially malicious activity where the legitimate ClickOnce Deployment Foundation Services (dfsvc.exe) spawns child processes not typically associated with its function, indicating possible payload execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Creation of Suspicious ClickOnce AppRef-ms Persistence File
    description: Detects the creation of an `.appref-ms` file in common user persistence locations (e.g., Startup folder) which could be used to establish persistence for a malicious ClickOnce application.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Threat actors are increasingly weaponizing Microsoft's ClickOnce deployment technology to facilitate malware delivery, achieve persistence, and maintain stealthy access on victim systems. This abuse, highlighted by CrowdStrike, allows attackers to bypass common security controls like email filters and traditional executable scrutiny, as ClickOnce applications often fly under the radar compared to standard `.exe` files. The technique is attractive due to its minimal user interaction requirement, enabling payload execution and installation without administrative privileges. A key aspect of this abuse is the ability for attackers to push malicious updates to previously installed "harmless" ClickOnce applications via their built-in update mechanism, effectively turning benign software into malware and providing a reliable method for long-term remote access and C2. The execution pathway often involves legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, further obscuring malicious activity. This widespread lack of awareness among users and security teams regarding ClickOnce risks makes it a potent and attractive attack vector for adversaries.

## Attack Chain

1.  **Initial Access**: Threat actors convince a target user (e.g., via a deceptive webpage or email link) to click a button or link that initiates a ClickOnce application deployment.
2.  **Execution**: The user clicks the `.application` file or web link, triggering the ClickOnce installation process on their Windows endpoint.
3.  **Defense Evasion & Execution**: The ClickOnce application installs without requiring administrative privileges, using legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe` to execute the initial payload, bypassing traditional security scrutiny for elevated privileges and process legitimacy.
4.  **Persistence**: If configured for offline availability, a shortcut (`.appref-ms` file) for the ClickOnce application is placed in the user's Start Menu (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\`) or other persistence locations (e.g., Startup folder, Scheduled Task).
5.  **Command and Control / Persistence**: Upon subsequent launch of the ClickOnce application (either manually or via persistence mechanism), the application checks for updates from the attacker-controlled deployment server, downloading and executing new malicious components without further user prompts.
6.  **Impact / Objectives**: The updated or initially deployed malicious payload performs actions such as data exfiltration, lateral movement, or ransomware deployment, leveraging the persistent and stealthy access achieved via ClickOnce.

## Impact

The abuse of ClickOnce technology allows threat actors to significantly reduce friction in malware delivery, making it easier to compromise endpoints. This vector bypasses traditional security controls, enabling stealthy execution within legitimate process trees (`rundll32.exe`, `dfsvc.exe`), and often requires no administrative privileges, broadening the scope of vulnerable targets. The inherent update mechanism in ClickOnce provides a robust channel for attackers to maintain persistent access and evolve their payloads without further user interaction, transforming initially benign applications into potent threats. If successful, organizations face compromised user accounts, potential data breaches, system control, and extended dwell times for adversaries.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM/EDR to detect suspicious ClickOnce-related activity.
*   Enable Sysmon Process Creation (Event ID 1) and File Creation (Event ID 11) logging to support the ClickOnce detection rules.
*   Implement strict application whitelisting or controls to prevent unauthorized ClickOnce application execution, particularly from untrusted sources.
*   Educate users on the risks associated with clicking links or downloading files that initiate application installations, especially those bypassing traditional `.exe` downloads.
*   Monitor processes `dfsvc.exe` and `rundll32.exe` for unusual child processes or network connections, as they are used in the ClickOnce execution chain.
*   Regularly audit `%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\` and other common persistence locations for newly created or modified `.appref-ms` files that are not explicitly authorized.
