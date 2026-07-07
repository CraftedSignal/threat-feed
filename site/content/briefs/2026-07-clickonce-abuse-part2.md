---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively exploiting Microsoft's ClickOnce technology to deliver and persist malware, enabling initial access and payload execution with minimal user interaction and bypassing traditional defenses by operating within legitimate Microsoft processes, without requiring elevated privileges.
date: "2026-07-07T12:31:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - malware-delivery
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - .application files
  - .appref-ms files
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors send phishing emails or host malicious websites, socially engineering users to click on a link that initiates a ClickOnce application deployment or download a .application file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce Persistence via Startup Folder (.appref-ms)
    description: Detects the creation of a ClickOnce application reference file (.appref-ms) directly within a user's Startup folder or a common Startup folder, indicating an attempt to establish persistence.
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
  - title: ClickOnce Persistence via Scheduled Task for .appref-ms
    description: Detects the creation of a scheduled task that executes a ClickOnce application reference file (.appref-ms), a technique used by attackers to maintain persistence.
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

Threat actors are increasingly abusing Microsoft's ClickOnce application deployment technology to facilitate malware delivery and persistence, as detailed in recent CrowdStrike research. This technique allows attackers to execute malicious payloads with minimal user interaction—often just a single click on a link or `.application` file—thereby bypassing common security controls like email filters and traditional executable scrutinization. The abuse began to gain prominence with Black Hat USA 2019 research by William Burke, and CrowdStrike has identified new variations. Attackers leverage ClickOnce's inherent user-friendliness and lack of awareness among users and security tools. The malicious code executes within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), enhancing stealth, and does not require administrative privileges, significantly lowering the barrier to attack. Furthermore, the built-in update mechanism of ClickOnce allows attackers to establish persistent remote access by pushing malicious updates to previously installed, seemingly benign applications.

## Attack Chain

1.  **Initial Access**: Threat actors send phishing emails or host malicious websites, socially engineering users to click on a link that initiates a ClickOnce application deployment or download a `.application` file.
2.  **Execution via ClickOnce**: The user clicks the link or `.application` file, triggering the ClickOnce deployment process, which installs and executes the application without requiring administrative privileges.
3.  **Stealthy Payload Launch**: The malicious payload is launched by legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, making its execution appear benign to many security tools.
4.  **Offline Installation & Persistence Setup**: If configured for offline availability, a shortcut (`.appref-ms` file) is dropped in the user's Start Menu (%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\).
5.  **Persistence Mechanism Deployment**: To ensure persistence, the adversary places this `.appref-ms` file in the Windows Startup folder (e.g., `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to automatically launch it.
6.  **Malicious Update Deployment**: The attacker compromises or controls the ClickOnce deployment server and pushes a malicious update to the application.
7.  **Re-execution and Update**: The next time the user logs in or the scheduled task runs, the `.appref-ms` file is opened, triggering the ClickOnce application to check for and download the malicious update.
8.  **Impact**: The updated, malicious payload executes, establishing C2, enabling remote access, further lateral movement, or data exfiltration.

## Impact

The abuse of ClickOnce technology poses a significant threat, enabling attackers to bypass common security controls and establish persistent access within an organization's environment. If successful, this can lead to the execution of arbitrary malware, remote compromise of endpoints, and potential lateral movement across the network. The stealthy nature of executing within legitimate Microsoft processes makes detection challenging, increasing the dwell time for attackers. Organizations could face data exfiltration, ransomware deployment, or complete system compromise, all initiated without requiring elevated privileges, affecting the majority of enterprise endpoints running standard user accounts.

## Recommendation

*   Enable Sysmon file event and process creation logging to activate the rules below and gain visibility into ClickOnce activity.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, focusing on detections for `.appref-ms` files used for persistence.
*   Monitor for the creation of `.appref-ms` files in unusual directories, particularly the Startup folder.
*   Inspect `schtasks.exe` command lines for references to `.appref-ms` files, indicating suspicious scheduled task creation.
*   Educate users about the risks of installing software from untrusted sources, even if it appears to be a legitimate application or installer.
