---
title: New Abuse of ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly exploiting Microsoft's ClickOnce application deployment technology to deliver malware, bypass traditional security controls, and establish persistence on target systems, leveraging its legitimate update mechanism for ongoing command and control.
date: "2026-07-07T04:25:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - .NET Framework
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system... clicking a webpage button can trigger software installation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed... clicking a webpage button can trigger software installation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms File Creation in Startup Folder
    description: Detects the creation of ClickOnce application reference files (.appref-ms) within a user's Startup folder, which adversaries can use for persistence. This technique allows malware to execute automatically upon user login.
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
    description: Detects the creation of scheduled tasks (`schtasks.exe`) that are configured to launch ClickOnce application reference files (.appref-ms). This is a known technique for adversaries to establish persistence and ensure malware execution.
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

CrowdStrike has observed a new wave of abuse involving Microsoft's ClickOnce technology, where threat actors weaponize its features to facilitate malware delivery and persistence. This abuse is attractive to adversaries due to the minimal user interaction required for deployment, often bypassing traditional security mechanisms like email filters and avoiding scrutiny common for executable files. ClickOnce applications, identifiable by their `.application` and `.appref-ms` file extensions, can be installed without elevated privileges, making standard user accounts vulnerable. A significant advantage for attackers is the legitimate appearance of the deployment process, executing payloads within trusted Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. Furthermore, the built-in update mechanism allows adversaries to maintain remote access, update malware, and potentially facilitate lateral movement, posing a persistent and stealthy threat that defenders must actively monitor.

## Attack Chain

1.  **Initial Access**: Threat actors employ social engineering tactics, often via malicious links or webpage buttons, to convince targets to initiate the download and execution of a malicious ClickOnce application.
2.  **Execution via ClickOnce**: Upon user interaction, the malicious `.application` file is downloaded and executed, leveraging the legitimate ClickOnce deployment process to deploy the attacker's payload.
3.  **Payload Deployment**: The ClickOnce application installs malicious components onto the system, often dropping an `.appref-ms` file, which is an application reference used to launch the ClickOnce app.
4.  **Persistence (Startup Folder)**: The attacker configures the malicious ClickOnce application to drop its `.appref-ms` shortcut file into the user's Start Menu Startup folder (e.g., `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`).
5.  **Persistence (Scheduled Task)**: Alternatively, attackers create a scheduled task to automatically launch the `.appref-ms` file at predetermined intervals or system events.
6.  **Defense Evasion & Execution**: The malicious payload, once initiated by the `.appref-ms` file, executes within the context of legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, masking its malicious activity.
7.  **Command and Control / Updates**: The ClickOnce application's inherent update mechanism is leveraged by the attacker to fetch new malicious components, maintain persistent remote access, update C2 addresses, or support lateral movement.
8.  **Impact**: The compromised system becomes a platform for further malicious activities, including data exfiltration, system damage, or serving as an entry point for broader network compromise.

## Impact

The abuse of ClickOnce technology allows threat actors to deliver and execute malware with high success rates due to minimal user friction and the bypassing of common security controls. If successful, organizations face significant risks including persistent compromise of endpoints, unauthorized remote access, potential for data exfiltration, and the ability for attackers to update and evolve their malicious tools on compromised systems. The use of legitimate Windows processes for execution makes detection challenging, leading to prolonged dwell times and potential for broader network infiltration and financial loss.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Enable comprehensive file system monitoring to detect the creation of `.appref-ms` files in critical user directories, especially Startup folders.
*   Monitor for the creation of new scheduled tasks that reference `.appref-ms` files or other unusual executable types.
*   Implement strong application control policies to restrict the execution of unsigned or untrusted ClickOnce applications.
*   Educate users on the risks associated with clicking suspicious links or downloading software from unverified sources, even if it appears to be a legitimate software installation prompt.
