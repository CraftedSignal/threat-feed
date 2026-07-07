---
title: New Abuse of ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively exploiting Microsoft's ClickOnce technology by leveraging its simplified deployment and automatic update features to deliver malware, achieve persistence through `.appref-ms` files in the Startup folder, and maintain stealthy remote access via legitimate processes like `rundll32.exe` and `dfsvc.exe`.
date: "2026-07-04T07:57:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - malware
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
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
iocs:
  - type: file_extension
    value: .application
  - type: file_extension
    value: .appref-ms
  - type: process
    value: rundll32.exe
  - type: process
    value: dfsvc.exe
ioc_counts:
  file_extension: 2
  process: 2
rules:
  - title: ClickOnce Persistence via Appref-ms in Startup Folder
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) within a user's Startup folder, indicating an attempt to establish persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Threat actors are increasingly abusing Microsoft's ClickOnce technology as a sophisticated mechanism for malware delivery, persistence, and covert remote access. This abuse exploits the inherent user-friendliness of ClickOnce, which allows applications to be deployed with minimal user interaction and without requiring elevated privileges. Adversaries capitalize on the general lack of awareness regarding `.application` and `.appref-ms` file types, often bypassing traditional security defenses that scrutinize `.exe` files. The technique involves convincing users to click misleading buttons or malicious `.application` files. Once a (potentially benign) ClickOnce application is installed, threat actors leverage its built-in update mechanism to push malicious payloads. This updated malware then executes stealthily within legitimate Microsoft processes, such as `rundll32.exe` and `dfsvc.exe`, facilitating persistence by placing `.appref-ms` shortcuts in the Startup folder or via scheduled tasks, ultimately enabling long-term remote access and control.

## Attack Chain

1.  **Initial Access**: Threat actors initiate the attack by convincing a target user to click on a malicious link or download and open a weaponized `.application` file, often disguised as a legitimate software update or document.
2.  **Initial Execution**: Upon user interaction, the ClickOnce deployment process begins, installing an application (which may initially appear benign) without requiring administrative privileges, leveraging the technology's simplified installation flow.
3.  **Shortcut Placement**: A `.appref-ms` shortcut file is automatically created in the user's Start Menu directory (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) to launch the installed ClickOnce application.
4.  **Persistence Establishment**: To ensure long-term presence, the threat actor manipulates the system to launch the `.appref-ms` file automatically, either by moving or creating a copy in the user's Startup folder (e.g., `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\`) or by creating a scheduled task that executes the `.appref-ms` file.
5.  **Malicious Update Push**: The threat actor, having control over the ClickOnce deployment server (either by compromise or initial setup), pushes a malicious update for the installed application.
6.  **Malicious Payload Execution**: When the user next launches the ClickOnce application (either manually or via the persistence mechanism), the `.appref-ms` file triggers an update check. The malicious update is silently downloaded and executed.
7.  **Defense Evasion & Impact**: The malicious payload often executes within legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`, blending in with normal system activity to evade detection and achieve objectives such as remote access, data exfiltration, or further compromise.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common security defenses, gain a persistent foothold in target environments, and maintain stealthy remote access. The low-privilege installation and the use of legitimate Microsoft processes for execution mean that attacks can go undetected for extended periods. This can lead to sensitive data exfiltration, deployment of additional malware, lateral movement within the network, and ultimately, significant financial and reputational damage to affected organizations. The widespread lack of awareness about ClickOnce risks across user bases and security teams further exacerbates the potential for successful exploitation.

## Recommendation

*   Deploy the Sigma rule detecting `.appref-ms` file creation in Startup folders to identify persistence attempts.
*   Implement strong application whitelisting policies to prevent the execution of untrusted ClickOnce applications.
*   Enhance logging for process creation, specifically monitoring `rundll32.exe` and `dfsvc.exe` for unusual command-line arguments or child processes.
*   Educate users on the risks associated with ClickOnce applications and the implications of clicking on `.application` files or unusual installation prompts.
