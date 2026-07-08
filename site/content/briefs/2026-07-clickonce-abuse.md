---
title: Threat Actors Abuse ClickOnce Technology for Persistent Malware Delivery
slug: 2026-07-clickonce-abuse
description: Threat actors are exploiting Microsoft's ClickOnce technology to deploy malware with minimal user interaction, bypassing traditional defenses, gaining persistence via update mechanisms and startup entries, and executing payloads stealthily within legitimate processes, leading to remote access, command and control, and lateral movement.
date: "2026-07-08T06:13:51Z"
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
  - windows
  - malware
vendors:
  - Microsoft
products:
  - ClickOnce Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: clicking a webpage button can trigger software installation
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: .application files can sometimes fly under the radar of security tools
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task to process the file regularly
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence via Startup Folder
    description: Detects the creation of .appref-ms files within user Startup folders, indicating a potential persistence mechanism used by threat actors abusing ClickOnce technology.
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
rules_count: 1
---

Threat actors are actively abusing Microsoft's ClickOnce technology, a legitimate application deployment framework, to deliver malware with high stealth and minimal user interaction. This abuse, documented by CrowdStrike as a significant threat as of June 2026, exploits ClickOnce's user-friendly installation process, bypassing traditional defenses that scrutinize `.exe` files more heavily than `.application` files. Attackers leverage the fact that ClickOnce apps do not require elevated privileges, making standard user accounts vulnerable. A key aspect of this technique is the built-in update mechanism: once an initial, potentially benign, ClickOnce application is installed and its `.appref-ms` shortcut created in the Start Menu, adversaries can push malicious updates to their deployment servers. The next time the user launches the application, the malicious payload is downloaded and executed stealthily within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, without further user prompting. This method grants persistent remote access, enables command and control (C2), and facilitates lateral movement, highlighting a critical blind spot for many organizations.

## Attack Chain

1.  **Initial Access**: Threat actors convince targets to click on a malicious ClickOnce application link embedded in a webpage or delivered as an `.application` file.
2.  **Initial Execution**: The user is prompted to install the ClickOnce application, requiring minimal interaction, leading to its initial deployment on the system.
3.  **Persistence (AppRef-ms Shortcut)**: An `.appref-ms` file, acting as an application shortcut, is dropped in the `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\` folder.
4.  **Malicious Update Push**: After compromising legitimate application servers or through social engineering, threat actors push a malicious update to the ClickOnce deployment server.
5.  **Execution of Malicious Update**: When the user subsequently launches the ClickOnce application via the `.appref-ms` shortcut from the Start Menu, the malicious update is fetched, downloaded, and executed without further user authorization.
6.  **Stealthy Execution**: The malicious payload executes within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, increasing stealth and evading detection.
7.  **Persistence (Alternative)**: To ensure consistent execution, attackers can place the `.appref-ms` file directly in the Windows Startup folder or configure a scheduled task to regularly open the file.
8.  **Impact**: Successful exploitation grants threat actors persistent remote access, enables command and control (C2) communications, and facilitates lateral movement within the compromised network.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access to target systems with minimal effort and high stealth. This can lead to significant data exfiltration, deployment of additional malware (e.g., ransomware), and complete network compromise. The ease of deployment, lack of elevated privilege requirements, and built-in updating mechanism make this a potent vector for long-term presence. While specific victim counts are not detailed, the technique targets standard user accounts across various sectors, making a wide range of organizations vulnerable to unauthorized remote access and network control if not adequately defended against.

## Recommendation

*   Deploy the Sigma rule `Detect ClickOnce Appref-ms Persistence via Startup Folder` to identify `.appref-ms` file creation in Windows Startup folders.
*   Configure `process_creation` logging to capture command-line arguments for `rundll32.exe` and `dfsvc.exe`, and develop behavioral analytics to detect unusual child processes or network connections originating from these binaries outside of known ClickOnce application updates.
*   Implement egress filtering and monitor `network_connection` logs to block or alert on `rundll32.exe` or `dfsvc.exe` communicating with suspicious external IP addresses or domains indicative of C2 activity.
*   Strengthen security awareness training to educate users about the risks associated with untrusted ClickOnce applications and `.application` files, aligning with the initial access techniques `T1204.001` and `T1204.002`.
