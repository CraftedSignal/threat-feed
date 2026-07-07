---
title: New Abuse of ClickOnce Technology for Persistent Access
slug: 2026-07-clickonce-abuse
description: Threat actors are actively weaponizing Microsoft's ClickOnce technology, using its legitimate features to deploy malicious applications, achieve persistence without elevated privileges, bypass traditional security defenses, and maintain remote access through built-in update mechanisms, enabling stealthy execution within legitimate Microsoft processes.
date: "2026-07-07T15:55:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - microsoft-windows
  - living-off-the-land
vendors:
  - Microsoft
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically... For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically... creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce application reference file (.appref-ms) in a user's Startup folder, which adversaries can use for persistence without administrative privileges.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: ClickOnce Persistence via Scheduled Task Creation
    description: Detects the creation of a scheduled task (using schtasks.exe) designed to execute a ClickOnce application reference file (.appref-ms) for persistence.
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

CrowdStrike has identified new abuses of Microsoft's ClickOnce technology, wherein threat actors are leveraging its inherent features for malicious purposes. The ease of deployment, requiring minimal user interaction (just a click or two), allows attackers to bypass common security controls like mailbox filters. A general lack of awareness about `.application` and `.appref-ms` files compared to `.exe` files helps these applications "fly under the radar." Crucially, ClickOnce apps do not require administrative privileges for installation, lowering the barrier to entry for attackers targeting standard user accounts. Furthermore, the built-in update mechanism provides a robust method for persistence, allowing adversaries to update malware, change Command and Control (C2) addresses, or move laterally. Malicious payloads execute stealthily within legitimate Microsoft process trees, specifically via `rundll32.exe` and `dfsvc.exe`, making detection challenging. This sophisticated abuse enables threat actors to establish and maintain long-term access to target systems.

## Attack Chain

1.  **Initial Access**: Threat actors employ social engineering tactics, such as luring users with deceptive webpage buttons or malicious links, to convince them to click and initiate the deployment of a seemingly benign ClickOnce application.
2.  **Deployment**: Upon user interaction, a malicious `.application` file is downloaded and executed, triggering the installation process for the ClickOnce application.
3.  **Local Installation**: The ClickOnce application is installed in the user's profile, and if configured for offline availability, an `.appref-ms` shortcut file is dropped into the Windows Start Menu (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Stealthy Execution**: The initial malicious payload or application components execute within legitimate Microsoft process trees, typically parented by `dfsvc.exe` (Deployment Framework Services) and subsequently invoking `rundll32.exe`.
5.  **Persistence Establishment**: To maintain access, adversaries place the `.appref-ms` file into a user's Startup folder or configure a scheduled task to regularly execute the `.appref-ms` file.
6.  **Malware Update & Evolution**: Leveraging the legitimate built-in update mechanism of ClickOnce, threat actors push malicious updates to the application's deployment server. The next time the user launches the application via its shortcut, the updated, malicious payload is downloaded and executed without further user prompts.
7.  **Command and Control**: The updated malware establishes persistent remote access, enabling C2 communication, data exfiltration, lateral movement, or other post-exploitation activities.

## Impact

The abuse of ClickOnce technology significantly lowers the bar for attackers to gain initial access and establish persistence on enterprise endpoints. Since administrative privileges are not required, standard user accounts, which comprise the majority of corporate users, are highly vulnerable. The ability to execute within legitimate Microsoft processes (dfsvc.exe, rundll32.exe) and bypass traditional security tools means malicious activity can go undetected for extended periods, leading to prolonged compromise. The built-in update mechanism provides a resilient pathway for adversaries to refresh their malware, modify C2 infrastructure, and adapt to defensive measures, resulting in sustained remote access, potential data theft, and further network compromise without requiring repeat initial access efforts.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically focusing on `ClickOnce_Persistence_Startup` and `ClickOnce_Persistence_ScheduledTask`.
*   Enable comprehensive file creation and modification logging for user `AppData` directories to detect suspicious `.appref-ms` file placements as targeted by the `ClickOnce_Persistence_Startup` rule.
*   Enable process creation logging for `schtasks.exe` and its command-line arguments to identify the creation of scheduled tasks that trigger `.appref-ms` files, as detected by the `ClickOnce_Persistence_ScheduledTask` rule.
*   Educate users on the risks associated with unexpected software installations triggered by web links or seemingly innocuous files, particularly those not originating from trusted enterprise application stores.
