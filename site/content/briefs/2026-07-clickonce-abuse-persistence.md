---
title: New ClickOnce Abuse for Persistence and Evasion
slug: 2026-07-clickonce-abuse-persistence
description: Threat actors are exploiting Microsoft's ClickOnce technology to bypass security controls, achieve persistence, and maintain command and control by leveraging its user-friendly deployment, built-in update mechanism, and execution within legitimate Microsoft processes.
date: "2026-07-06T07:03:50Z"
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
  - microsoft
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
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
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
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence in Startup Folder
    description: Detects the creation of .appref-ms files in a user's Startup folder, a known method for ClickOnce persistence abuse.
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
  - title: Detect Scheduled Task Modifying ClickOnce Appref-ms
    description: Detects the use of schtasks.exe to create or modify a scheduled task that launches a ClickOnce .appref-ms file, a known method for persistence.
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

Threat actors are increasingly abusing Microsoft's ClickOnce technology to deliver malware, achieve initial execution, and maintain long-term persistence on compromised systems. This new abuse, observed by CrowdStrike, takes advantage of ClickOnce's minimal user interaction requirement for application deployment, often bypassing traditional security mechanisms like mailbox filters that scrutinize `.exe` files. Attackers exploit the general lack of awareness regarding ClickOnce applications, making malicious `.application` files appear less suspicious to users and security tools. A key tactic involves leveraging ClickOnce's automatic update mechanism to push malicious payloads and alter command-and-control (C2) configurations without user authorization. Furthermore, adversaries achieve robust persistence by strategically placing `.appref-ms` shortcut files in Windows Startup folders or integrating them into scheduled tasks, ensuring malware re-execution. The malicious activity benefits from stealth, as payloads execute within legitimate Microsoft process trees (e.g., `rundll32.exe`, `dfsvc.exe`), making detection challenging.

## Attack Chain

1.  **Initial Access**: Threat actors employ phishing techniques (e.g., malicious emails, compromised websites) to entice users into clicking a link or downloading a file.
2.  **Payload Delivery**: The user clicks a link that initiates a ClickOnce deployment or downloads a malicious `.application` file (a ClickOnce manifest).
3.  **Initial Execution**: The ClickOnce client (typically part of the .NET Framework Deployment Service, `dfsvc.exe`, or via `rundll32.exe`) downloads and executes the initial application package from a remote server, often installing it in `C:\Users\[user]\AppData\Local\Apps\2.0`.
4.  **Defense Evasion & Privilege Escalation (Implicit)**: The malicious application executes within legitimate Microsoft process trees (e.g., `rundll32.exe` and `dfsvc.exe`), and its deployment does not require elevated administrative privileges, allowing standard user accounts to be compromised.
5.  **Persistence (Initial Deployment)**: If the ClickOnce application is configured for offline availability, an `.appref-ms` shortcut file is dropped in the user's Start Menu (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) to launch the application.
6.  **Persistence (Update Mechanism)**: Adversaries push malicious updates to the ClickOnce deployment server. When the user next launches the application via its `.appref-ms` shortcut, the ClickOnce client automatically fetches and executes the updated malicious payload without further user prompts.
7.  **Persistence (Further Mechanisms)**: Threat actors modify system settings to ensure the malicious ClickOnce application automatically runs, such as by placing the `.appref-ms` file directly into the Windows Startup folder or creating a scheduled task to execute the `.appref-ms` file at system startup or regular intervals.
8.  **Impact**: The persistent malicious application enables remote access, command and control (C2), data exfiltration, or the deployment of additional malware without requiring repeated user interaction or elevated privileges.

## Impact

The abuse of ClickOnce technology allows threat actors to establish covert and persistent access to victim networks, often bypassing conventional endpoint security measures due to the perceived legitimacy of ClickOnce processes and the lack of user scrutiny for `.application` files. Successful exploitation leads to unauthorized remote access, facilitating data exfiltration, lateral movement within the network, and the deployment of further malware such as ransomware or infostealers. Victims include organizations across various sectors, as the technique targets a ubiquitous Microsoft technology. The stealthy nature of this attack makes it difficult to detect, enabling long-term compromise and significant financial and reputational damage.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Enable Sysmon file event logging (Event ID 11) and process creation logging (Event ID 1) to activate the rules above.
*   Monitor for the creation of `.appref-ms` files in user Startup folders (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`).
*   Monitor for the creation or modification of scheduled tasks (`schtasks.exe`) that launch `.appref-ms` files.
*   Educate users on the risks associated with clicking on untrusted links and downloading unfamiliar files, especially those with `.application` extensions.
